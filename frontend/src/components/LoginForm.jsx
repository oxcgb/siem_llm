import React, { useState } from 'react';
import {
  Card, Form, Input, Button,
  Tabs, Alert, Space, message
} from 'antd';
import { UserOutlined } from '@ant-design/icons';
import api, { setToken } from '../api';

export default function LoginForm({ adAvailable, onSuccess }) {
  const [form] = Form.useForm();
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState('ad');

  const onFinish = async (v) => {
    setBusy(true);
    try {
      const res = await api('/api/auth/login', {
        method: 'POST',
        body: { ...v, method: tab },
        auth: false,
        timeout: 15000
      });
      setToken(res.token);
      message.success('OK: ' + res.username);
      onSuccess(res);
    } catch (e) {
      if (e.message.includes('429')) {
        message.error('Too many attempts — wait a minute and try again');
      } else {
        message.error('Fail: ' + e.message);
      }
    }
    setBusy(false);
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#001529'
    }}>
      <Card
        title={<Space><UserOutlined /> SOC LLM Analyzer</Space>}
        style={{ width: 420 }}
      >
        <Tabs
          activeKey={tab}
          onChange={setTab}
          items={[
            { key: 'ad', label: 'Active Directory', disabled: !adAvailable },
            { key: 'local', label: 'Local' }
          ]}
        />
        <Form form={form} onFinish={onFinish}>
          <Form.Item
            name="username"
            rules={[{ required: true, message: 'name' }]}
          >
            <Input
              placeholder={tab === 'ad' ? 'Login' : 'Local'}
              autoFocus
            />
          </Form.Item>
          <Form.Item
            name="password"
            rules={[{ required: true, message: 'password' }]}
          >
            <Input.Password
              placeholder="Password"
              onPressEnter={() => form.submit()}
            />
          </Form.Item>
          {tab === 'ad' && !adAvailable && (
            <Alert type="warning" showIcon
              style={{ marginBottom: 12 }}
              message="AD not configured"
            />
          )}
          <Button type="primary" htmlType="submit" block loading={busy}>
            Login
          </Button>
        </Form>
      </Card>
    </div>
  );
}