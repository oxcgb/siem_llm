import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider } from 'antd'
import App from './App'
import ErrorBoundary from './components/ErrorBoundary'
import { loadDisplayTz } from './time'

loadDisplayTz().finally(() => {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <ErrorBoundary>
        <ConfigProvider>
          <App />
        </ConfigProvider>
      </ErrorBoundary>
    </React.StrictMode>
  )
})