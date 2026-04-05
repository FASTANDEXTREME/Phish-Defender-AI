import React from 'react';
import { AlertTriangle } from 'lucide-react';

const MetricCard = ({ title, icon: Icon, value, statusColor, children, detailRow = false, degraded = false }) => {
  return (
    <div className={`glass-panel p-5 relative overflow-hidden group ${degraded ? 'border-amber-500/20' : ''}`}>
      {/* Hover glow */}
      <div className="absolute inset-0 bg-gradient-to-br from-white/[0.01] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className={`p-2.5 rounded-lg bg-dark-800 border ${degraded ? 'border-amber-500/20' : 'border-white/[0.05]'}`}>
             <Icon className={`w-5 h-5 ${degraded ? 'text-amber-500' : statusColor}`} />
          </div>
          <h3 className="text-gray-300 font-semibold tracking-wide text-sm uppercase">{title}</h3>
        </div>
        <div className="flex items-center space-x-2">
          {degraded && (
            <span className="flex items-center space-x-1 px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-400 text-[10px] font-bold tracking-wider uppercase">
              <AlertTriangle className="w-3 h-3" />
              <span>Degraded</span>
            </span>
          )}
          {value !== undefined && (
            <div className="text-xl font-bold text-white">
              {value}
            </div>
          )}
        </div>
      </div>

      <div className={`text-gray-400 text-sm ${detailRow ? 'space-y-2' : ''}`}>
        {children}
      </div>
    </div>
  );
};

export default MetricCard;

