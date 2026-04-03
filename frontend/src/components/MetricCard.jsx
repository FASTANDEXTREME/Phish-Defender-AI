import React from 'react';

const MetricCard = ({ title, icon: Icon, value, statusColor, children, detailRow = false }) => {
  return (
    <div className="glass-panel p-5 relative overflow-hidden group">
      {/* Hover glow */}
      <div className="absolute inset-0 bg-gradient-to-br from-white/[0.01] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-dark-800 border border-white/[0.05]">
             <Icon className={`w-5 h-5 ${statusColor}`} />
          </div>
          <h3 className="text-gray-300 font-semibold tracking-wide text-sm uppercase">{title}</h3>
        </div>
        {value !== undefined && (
          <div className="text-xl font-bold text-white">
            {value}
          </div>
        )}
      </div>

      <div className={`text-gray-400 text-sm ${detailRow ? 'space-y-2' : ''}`}>
        {children}
      </div>
    </div>
  );
};

export default MetricCard;
