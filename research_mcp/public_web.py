"""Read-only public HTTPS discovery. No credentials, proxies, internal targets or JS."""
from __future__ import annotations
import json
import re
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit,urlunsplit,urljoin,urlencode,unquote
from urllib.robotparser import RobotFileParser
from .fetch import PinnedHTTPSConnection,Response,USER_AGENT

MAX_BYTES=524288


def public_url(url):
    if not isinstance(url,str) or len(url)>2048 or any(ord(c)<33 for c in url):
        raise ValueError("Invalid public URL")
    p=urlsplit(url)
    if (p.scheme!="https" or not p.hostname or p.username or p.password or p.port not in (None,443)
            or "\\" in unquote(p.path) or any(x in {".",".."} for x in unquote(p.path).split("/"))):
        raise ValueError("Public HTTPS without credentials required")
    return urlunsplit(("https",p.netloc.lower(),p.path or "/",p.query,""))


def retrieve(url):
    deadline=time.monotonic()+25
    for _ in range(5):
        url=public_url(url);p=urlsplit(url)
        connection=PinnedHTTPSConnection(p.hostname,timeout=5,context=ssl.create_default_context())
        try:
            connection.request("GET",(p.path or "/")+("?"+p.query if p.query else ""),
                headers={"User-Agent":USER_AGENT,"Accept-Encoding":"identity"})
            response=connection.getresponse()
            headers={k.lower():v for k,v in response.getheaders()}
            if response.status in {301,302,303,307,308}:
                target=public_url(urljoin(url,headers.get("location","")))
                if urlsplit(target).netloc!=p.netloc:
                    raise ValueError("Cross-origin redirect must be queued separately")
                url=target;continue
            if headers.get("content-encoding","identity")!="identity":
                raise ValueError("Compressed content not accepted")
            if int(headers.get("content-length","0"))>MAX_BYTES:
                raise ValueError("Public page budget")
            chunks=[];total=0
            while True:
                if time.monotonic()>deadline:raise TimeoutError("Public read deadline")
                block=response.read1(min(16384,MAX_BYTES+1-total))
                if not block:break
                total+=len(block)
                if total>MAX_BYTES:raise ValueError("Public page budget")
                chunks.append(block)
            return Response(url,response.status,headers,b"".join(chunks))
        finally:connection.close()
    raise ValueError("Redirect limit")


class Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.hidden=0;self.text=[];self.links=[]
    def handle_starttag(self,tag,attrs):
        if tag in {"script","style"}:self.hidden+=1
        if tag=="a" and not self.hidden and len(self.links)<100:
            self.links.extend(v for k,v in attrs if k=="href" and v)
    def handle_endtag(self,tag):
        if tag in {"script","style"}:self.hidden=max(0,self.hidden-1)
    def handle_data(self,text):
        if not self.hidden:self.text.append(text)


class PublicWeb:
    def __init__(self,fetcher=retrieve):
        self.fetcher=fetcher;self.robots={};self.checked={}

    def page(self,url):
        url=public_url(url);p=urlsplit(url);origin=urlunsplit(("https",p.netloc,"","",""))
        if origin not in self.robots:
            response=self.fetcher(origin+"/robots.txt")
            parser=RobotFileParser()
            if response.status in {404,410}:parser.parse([])
            elif response.status==200:parser.parse(response.body.decode("utf-8","replace").splitlines())
            else:raise ValueError("Robots unavailable")
            self.robots[origin]=parser
        robot=self.robots[origin]
        if not robot.can_fetch(USER_AGENT,url):raise ValueError("Robots exclusion")
        delay=max(1,robot.crawl_delay(USER_AGENT) or 0)
        if delay>30:raise ValueError("Crawl delay exceeds run budget")
        remaining=delay-(time.monotonic()-self.checked.get(origin,0))
        if remaining>0:time.sleep(remaining)
        self.checked[origin]=time.monotonic()
        response=self.fetcher(url)
        # Redirects may change origin; do not bypass a destination's robots policy.
        if urlsplit(response.url).netloc!=p.netloc:
            raise ValueError("Cross-origin redirect requires a separately queued public URL")
        if response.status!=200:raise ValueError("Public source unavailable")
        media=response.headers.get("content-type","").split(";")[0]
        if media not in {"text/html","text/plain","text/markdown","application/json","application/xhtml+xml"}:
            raise ValueError("Unsupported public media")
        raw=response.body.decode("utf-8","replace")
        links=[]
        if media=="application/json":
            data=json.loads(raw)
            if p.hostname=="api.crossref.org":
                # Exclude author, affiliation, contact and funder metadata.
                items=data.get("message",{}).get("items",[])[:5]
                text=json.dumps([{"title":x.get("title",[]),"abstract":x.get("abstract",""),"DOI":x.get("DOI")} for x in items])
                links=[x.get("URL","").replace("http://doi.org/","https://doi.org/") for x in items]
            else:text=raw[:12000]
        elif "html" in media:
            parser=Parser();parser.feed(raw);text=" ".join(" ".join(parser.text).split());links=parser.links
        else:text=raw[:12000];links=re.findall(r"https://[^\s<>\"')]+",text)[:100]
        validated=[]
        for link in links:
            try:validated.append(public_url(urljoin(response.url,link)))
            except ValueError:pass
        return response,text[:12000],list(dict.fromkeys(validated))[:50]

    def search(self,query):
        # Official unauthenticated bibliographic discovery, not proof of findings.
        if not isinstance(query,str) or not 1<=len(query)<=160:
            raise ValueError("Research query budget")
        return self.page("https://api.crossref.org/works?"+urlencode({"query":query,"rows":5}))
