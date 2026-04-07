import React, { useState, useEffect } from 'react';
import { Search, ShieldAlert, ShieldCheck, ShieldOff, Loader2 } from 'lucide-react';
import { motion } from 'framer-motion';

const HeroSearch = ({ onSearch, isLoading }) => {
  const [domain, setDomain] = useState('');
  const [safeBrowsingEnabled, setSafeBrowsingEnabled] = useState(() => {
    try {
      const saved = localStorage.getItem('safeBrowsingEnabled');
      return saved !== null ? JSON.parse(saved) : true;
    } catch (e) {
      return true;
    }
  });

  const [phishtankEnabled, setPhishtankEnabled] = useState(() => {
    try {
      const saved = localStorage.getItem('phishtankEnabled');
      return saved !== null ? JSON.parse(saved) : true;
    } catch (e) {
      return true;
    }
  });

  useEffect(() => {
    localStorage.setItem('safeBrowsingEnabled', JSON.stringify(safeBrowsingEnabled));
  }, [safeBrowsingEnabled]);

  useEffect(() => {
    localStorage.setItem('phishtankEnabled', JSON.stringify(phishtankEnabled));
  }, [phishtankEnabled]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (domain.trim() && !isLoading) {
      onSearch(domain.trim(), safeBrowsingEnabled, phishtankEnabled);
    }
  };

  return (
    <div className="relative pt-32 pb-16 px-6 max-w-4xl mx-auto text-center">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary-600/10 rounded-full blur-[120px] pointer-events-none" />

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className="relative z-10"
      >
        <div className="inline-flex items-center space-x-2 px-4 py-2 rounded-full glass-panel mb-8 border-primary-500/20">
          <ShieldAlert className="w-4 h-4 text-primary-500" />
          <span className="text-sm font-semibold tracking-wide text-gray-300">Intelligent Threat Detection</span>
        </div>

        <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight text-white mb-6">
          Analyze Any <span className="text-primary-500 glow-text">Domain</span>
        </h1>
        
        <p className="text-lg md:text-xl text-gray-400 mb-12 max-w-2xl mx-auto font-light leading-relaxed">
          Instantly detect phishing attempts, brand impersonation, and malicious websites with our AI-driven analysis engine.
        </p>

        <form onSubmit={handleSubmit} className="relative max-w-2xl mx-auto flex items-center">
          <div className="absolute left-6 text-gray-500">
             <Search className="w-6 h-6" />
          </div>
          <input
            type="text"
            placeholder="Enter URL or domain (e.g., login.example.com)..."
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={isLoading}
            className="w-full h-16 pl-16 pr-40 bg-dark-800/80 border border-white/[0.1] rounded-2xl text-white text-lg placeholder-gray-500 focus:outline-none focus:border-primary-500 transition-colors shadow-[0_8px_32px_rgba(0,0,0,0.4)] backdrop-blur-md"
            autoComplete="off"
            spellCheck="false"
          />
          <button
            type="submit"
            disabled={isLoading || !domain.trim()}
            className="absolute right-2 top-2 bottom-2 px-8 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 hover:shadow-glow-primary transition-all disabled:opacity-50 disabled:hover:scale-100 disabled:cursor-not-allowed flex items-center justify-center min-w-[120px]"
          >
            {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Analyze"}
          </button>
        </form>

        <div className="mt-8 flex flex-col md:flex-row justify-center items-center gap-6 md:gap-10">
          {/* Safe Browsing Toggle */}
          <div className="flex items-center space-x-3">
            <button 
              type="button"
              onClick={() => setSafeBrowsingEnabled(!safeBrowsingEnabled)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50 ${safeBrowsingEnabled ? 'bg-primary-500' : 'bg-gray-600'}`}
              role="switch"
              aria-checked={safeBrowsingEnabled}
              disabled={isLoading}
            >
              <span className="sr-only">Toggle Google Safe Browsing</span>
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${safeBrowsingEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
            
            <div 
              className={`flex items-center space-x-2 text-sm ${isLoading ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} select-none`} 
              onClick={() => !isLoading && setSafeBrowsingEnabled(!safeBrowsingEnabled)}
            >
              {safeBrowsingEnabled ? (
                <ShieldCheck className="w-4 h-4 text-primary-400" />
              ) : (
                <ShieldOff className="w-4 h-4 text-gray-500" />
              )}
              <span className="text-gray-400">
                Google Safe Browsing: {safeBrowsingEnabled ? <span className="text-primary-400 font-medium tracking-wide">Enabled</span> : <span className="text-gray-500">Disabled</span>}
              </span>
            </div>
          </div>

          {/* PhishTank Toggle */}
          <div className="flex items-center space-x-3">
            <button 
              type="button"
              onClick={() => setPhishtankEnabled(!phishtankEnabled)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50 ${phishtankEnabled ? 'bg-primary-500' : 'bg-gray-600'}`}
              role="switch"
              aria-checked={phishtankEnabled}
              disabled={isLoading}
            >
              <span className="sr-only">Toggle PhishTank API</span>
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${phishtankEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
            
            <div 
              className={`flex items-center space-x-2 text-sm ${isLoading ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} select-none`} 
              onClick={() => !isLoading && setPhishtankEnabled(!phishtankEnabled)}
            >
              {phishtankEnabled ? (
                <ShieldCheck className="w-4 h-4 text-primary-400" />
              ) : (
                <ShieldOff className="w-4 h-4 text-gray-500" />
              )}
              <span className="text-gray-400">
                PhishTank API: {phishtankEnabled ? <span className="text-primary-400 font-medium tracking-wide">Enabled</span> : <span className="text-gray-500">Disabled</span>}
              </span>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default HeroSearch;
