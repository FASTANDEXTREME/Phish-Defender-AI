import React, { useEffect, useState } from 'react';
import { Shield, Zap, Server, Activity } from 'lucide-react';
import axios from 'axios';

const Navbar = () => {
  const [serverInfo, setServerInfo] = useState({ ip: '...', location: '...', api_key_active: false });

  useEffect(() => {
    // Fetch server info
    const fetchServerInfo = async () => {
        try {
            const res = await axios.get('/server_info');
            setServerInfo({
                ip: res.data.ip || 'Unknown',
                location: res.data.location || 'Unknown',
                api_key_active: res.data.api_key_active || false
            });
        } catch (error) {
            console.error("Failed to fetch server info", error);
        }
    };
    fetchServerInfo();
  }, []);

  return (
    <nav className="fixed top-0 w-full z-50 py-4 px-6 md:px-12 backdrop-blur-[20px] bg-dark-900/40 border-b border-white/[0.05]">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        
        {/* Brand */}
        <div className="flex items-center space-x-3 cursor-pointer select-none">
          <div className="relative flex items-center justify-center p-2 rounded-xl bg-primary-600/10 border border-primary-500/20 shadow-glow-primary">
            <Shield className="w-6 h-6 text-primary-500" strokeWidth={2.5} />
          </div>
          <div className="flex flex-col">
            <span className="text-xl font-bold tracking-tight text-white leading-tight">
              Phish<span className="text-primary-500 glow-text">Defender</span>
            </span>
            <span className="text-[10px] uppercase font-bold tracking-widest text-gray-500">
              AI Powered Security
            </span>
          </div>
        </div>

        {/* Server Info / Status */}
        <div className="hidden md:flex items-center space-x-6 text-sm text-gray-400 font-medium">
          <div className="flex items-center space-x-2">
            <Server className="w-4 h-4 text-gray-500" />
            <span>{serverInfo.ip}</span>
            <span className="text-gray-600 px-1">•</span>
            <span>{serverInfo.location}</span>
          </div>
          
          <div className="flex items-center space-x-2 bg-dark-800/80 px-3 py-1.5 rounded-full border border-white/[0.05]">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span className="text-emerald-400/90 text-xs uppercase tracking-wider font-semibold">
              Live Network
            </span>
          </div>
          
          {serverInfo.api_key_active && (
            <div className="flex items-center space-x-2" title="Google Safe Browsing Active">
              <Zap className="w-4 h-4 text-amber-400 fill-amber-400/20" />
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
