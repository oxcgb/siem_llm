import React from 'react';
import { Button, Result } from 'antd';

export default class ErrorBoundary extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('[UI] crashed:', error, info?.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <Result
          status="error"
          title="UI Error"
          subTitle={String(this.state.error?.message || this.state.error)}
          extra={
            <Button type="primary" onClick={() => window.location.reload()}>
              Reload
            </Button>
          }
        />
      );
    }
    return this.props.children;
  }
}