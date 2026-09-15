import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import { AdminProvider } from './lib/admin';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AdminProvider>
      <App />
    </AdminProvider>
  </React.StrictMode>
);
