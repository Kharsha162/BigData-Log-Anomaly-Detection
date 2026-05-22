import React from 'react';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import SparkEngine from '../components/SparkEngine';

const SparkAnalytics = () => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#060814] text-gray-200">
      {/* Platform Navigation Sidebar */}
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Dash Header */}
        <Header title="APACHE SPARK DISTRIBUTED ANALYTICS ENGINE" />
        
        {/* Main Content Workspace */}
        <main className="flex-1 overflow-y-auto px-6 py-6 bg-darkBg">
          <SparkEngine />
        </main>
      </div>
    </div>
  );
};

export default SparkAnalytics;
