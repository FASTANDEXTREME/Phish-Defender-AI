import React, { useState } from 'react';
import axios from 'axios';
import Navbar from './components/Navbar';
import HeroSearch from './components/HeroSearch';
import Dashboard from './components/Dashboard';
import ScanningAnimation from './components/ScanningAnimation';
import { AnimatePresence } from 'framer-motion';

function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSearch = async (domain, safeBrowsingEnabled, phishtankEnabled) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      // Clean up input in frontend just in case
      let cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
      
      const res = await axios.get('/analyze', {
        params: { 
          domain: cleanDomain, 
          safebrowsing: safeBrowsingEnabled,
          phishtank: phishtankEnabled 
        }
      });
      setResult(res.data);
    } catch (err) {
      if (err.response && err.response.data && err.response.data.error) {
        setError(err.response.data.error);
      } else {
        setError("An unexpected error occurred during analysis.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-900 text-gray-200 font-sans selection:bg-primary-500/30 selection:text-white relative overflow-hidden">
      {/* Global Background elements */}
      <div className="fixed inset-0 bg-[url('https://www.transparenttextures.com/patterns/stardust.png')] opacity-20 pointer-events-none mix-blend-overlay"></div>
      
      <Navbar />

      <main className="relative z-10 pt-16">
        <HeroSearch onSearch={handleSearch} isLoading={isLoading} />
        
        {error && (
            <div className="max-w-2xl mx-auto px-6 mb-10">
                <div className="p-4 border border-primary-500/30 bg-primary-900/40 text-primary-500 rounded-xl backdrop-blur-md">
                    <span className="font-bold mr-2">Error:</span> {error}
                </div>
            </div>
        )}

        <AnimatePresence mode="wait">
           {isLoading && <ScanningAnimation key="loading" isVisible={isLoading} />}
           {!isLoading && result && !error && <Dashboard key="dashboard" result={result} />}
        </AnimatePresence>
      </main>
    </div>
  );
}

export default App;
