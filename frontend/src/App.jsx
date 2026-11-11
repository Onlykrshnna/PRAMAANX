/**
 * PRAMAANX - Primary Application Component & Route Configuration
 * Configures ThemeProvider, React Router with MainLayout, and laboratory page routes.
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import MainLayout from './components/layout/MainLayout';
import Home from './pages/Home';
import NewAnalysis from './pages/NewAnalysis';
import AnalysisResults from './pages/AnalysisResults';
import Investigations from './pages/Investigations';
import EvidenceVault from './pages/EvidenceVault';
import Reports from './pages/Reports';
import Learn from './pages/Learn';
import About from './pages/About';
import Dashboard from './pages/Dashboard';
import Settings from './pages/Settings';
import { ROUTES } from './utils/constants';

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Home />} />
            <Route path={ROUTES.ANALYZE.slice(1)} element={<NewAnalysis />} />
            <Route path={ROUTES.RESULTS.slice(1)} element={<AnalysisResults />} />
            <Route path="analysis/results/batch/:batchId" element={<AnalysisResults />} />
            <Route path="analysis/results/batch/:batchId/:fileId" element={<AnalysisResults />} />
            <Route path="results/batch/:batchId" element={<AnalysisResults />} />
            <Route path="results/batch/:batchId/:fileId" element={<AnalysisResults />} />
            <Route path="results" element={<AnalysisResults />} />
            <Route path={ROUTES.INVESTIGATIONS.slice(1)} element={<Investigations />} />
            <Route path={ROUTES.VAULT.slice(1)} element={<EvidenceVault />} />
            <Route path={ROUTES.REPORTS.slice(1)} element={<Reports />} />
            <Route path={ROUTES.LEARN.slice(1)} element={<Learn />} />
            <Route path={ROUTES.ABOUT.slice(1)} element={<About />} />
            <Route path={ROUTES.DASHBOARD.slice(1)} element={<Dashboard />} />
            <Route path={ROUTES.SETTINGS.slice(1)} element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}
