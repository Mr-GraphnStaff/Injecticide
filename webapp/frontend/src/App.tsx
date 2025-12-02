import { BrowserRouter, Route, Routes, useNavigate } from 'react-router-dom';
import ResultsPage from './components/results/ResultsPage';
import Console from './pages/Console';
import Home from './pages/Home';

const HomeRoute = () => {
    const navigate = useNavigate();
    return <Home onLaunch={() => navigate('/console')} />;
};

const ConsoleRoute = () => {
    const navigate = useNavigate();
    return <Console onBack={() => navigate('/')} />;
};

const ResultsRoute = () => <ResultsPage />;

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<HomeRoute />} />
                <Route path="/console" element={<ConsoleRoute />} />
                <Route path="/results/:runId" element={<ResultsRoute />} />
            </Routes>
        </BrowserRouter>
    );
}

export default App;
