# Update imports in webapp/api.py to use endpoints_new.py

# Read the file
with open('webapp/api.py', 'r') as f:
    content = f.read()

# Replace the import
content = content.replace(
    'from endpoints import AnthropicEndpoint, OpenAIEndpoint, AzureOpenAIEndpoint',
    'from endpoints_new import AnthropicEndpoint, OpenAIEndpoint, AzureOpenAIEndpoint'
)

# Also replace in main.py if it exists
try:
    with open('main.py', 'r') as f:
        main_content = f.read()
    
    main_content = main_content.replace(
        'from endpoints import',
        'from endpoints_new import'
    )
    
    with open('main.py', 'w') as f:
        f.write(main_content)
    print("Updated main.py")
except:
    pass

# Write back
with open('webapp/api.py', 'w') as f:
    f.write(content)
    
print("Updated webapp/api.py to use endpoints_new")
