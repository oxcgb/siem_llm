import React, { useState } from 'react';
import {
  Layout, Menu, Button, Space, Tag, Typography
} from 'antd';
import {
  DashboardOutlined, ApiOutlined, BugOutlined,
  SafetyOutlined, AlertOutlined, LinkOutlined,
  SettingOutlined, InfoCircleOutlined,
  LogoutOutlined, FileSearchOutlined, CloudOutlined
} from '@ant-design/icons';

import { useAuth } from './hooks/useAuth';
import LoginForm from './components/LoginForm';
import Dashboard from './pages/Dashboard';
import DataSources from './pages/DataSources';
import Incidents from './pages/Incidents';
import VpnPage from './pages/VpnPage';
import AdPage from './pages/AdPage';
import MultiPage from './pages/MultiPage';
import NetworkPage from './pages/NetworkPage';
import Playbooks from './pages/Playbooks';
import Settings from './pages/Settings';
import About from './pages/About';
import Audit from './pages/Audit';

const { Header, Sider, Content } = Layout;
const { Title, Text } = Typography;

export default function App() {
  const [page, setPage] = useState('dashboard');
  const { authMode, authUser, ldapReady, login, logout } = useAuth();

  if (authMode === 'ad' && !authUser) {
    return (
      <LoginForm adAvailable={ldapReady} onSuccess={login} />
    );
  }

  const pages = {
    dashboard: <Dashboard />,
    datasources: <DataSources />,
    playbooks: <Playbooks />,
    vpn: <VpnPage />,
    ad: <AdPage />,
    multi: <MultiPage />,
    network: <NetworkPage />,
    incidents: <Incidents />,
    settings: <Settings authMode={authMode} authUser={authUser} />,
    audit: <Audit />,
    about: <About />
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={200} style={{ background: '#001529' }}>
        <div style={{
          color: 'white', padding: '20px',
          textAlign: 'center', fontWeight: 'bold',
          fontSize: '16px'
        }}>SIEM Analyzer</div>
        <Menu theme="dark" selectedKeys={[page]}
          onClick={e => setPage(e.key)}
          items={[
            { key: 'dashboard', icon: <DashboardOutlined />, label: 'Dashboard' },
            { key: 'datasources', icon: <ApiOutlined />, label: 'Sources' },
            { key: 'playbooks', icon: <BugOutlined />, label: 'Playbooks' },
            { key: 'vpn', icon: <SafetyOutlined />, label: 'VPN' },
            { key: 'ad', icon: <SafetyOutlined />, label: 'AD' },
            { key: 'multi', icon: <AlertOutlined />, label: 'Multi' },
            { key: 'network', icon: <CloudOutlined />, label: 'Network' },
            { key: 'incidents', icon: <LinkOutlined />, label: 'Incidents' },
            { key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
            { key: 'audit', icon: <FileSearchOutlined />, label: 'Audit' },
            { key: 'about', icon: <InfoCircleOutlined />, label: 'About' }
          ]}
        />
      </Sider>
      <Layout>
        <Header style={{
          background: '#fff', padding: '0 20px',
          display: 'flex', justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <Title level={4} style={{ margin: '14px 0' }}>
            SOC LLM Analyst
          </Title>
          {authMode === 'ad' && authUser && (
            <Space>
              <Text strong>{authUser.display_name || authUser.username}</Text>
              {authUser.is_admin && <Tag color="gold">admin</Tag>}
              <Button icon={<LogoutOutlined />} onClick={logout}>Logout</Button>
            </Space>
          )}
        </Header>
        <Content style={{ margin: '20px' }}>
          {pages[page] || pages.dashboard}
        </Content>
      </Layout>
    </Layout>
  );
}