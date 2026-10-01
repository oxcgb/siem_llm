import React, { useState, useEffect } from 'react';
import {
  Alert, Button, Card, Form, Input,
  Popconfirm, Select, Switch, Tabs,
  message, Typography
} from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import api from '../api';
import AdSettingsTab from '../components/AdSettingsTab';
import VllmTab from '../components/VllmTab';
import TelegramTab from '../components/TelegramTab';

const { Text } = Typography;

export default function Settings({ authMode, authUser }) {
  const isAdmin = authMode !== 'ad' || !!authUser?.is_admin;

  const [ttl, setTtl] = useState(1);
  const [triage, setTriage] = useState({
    auto_triage_enabled: true
  });
  const [loading, setLoading] = useState(false);
  const [promptForm] = Form.useForm();
  const [savingPrompt, setSavingPrompt] = useState(false);

  useEffect(() => {
    if (!isAdmin) return; // admin tabs not mounted -> no requests
    api('/api/auth/ttl')
      .then(d => setTtl(d.ttl_hours || 1))
      .catch(() => {});
    api('/api/triage-status')
      .then(d => setTriage(d))
      .catch(() => {});
    api('/api/settings/prompt')
      .then(d => {
        promptForm.setFieldsValue({ prompt: d?.prompt || '' });
      })
      .catch(() => {});
  }, [isAdmin]);

  const changeTtl = async (v) => {
    await api('/api/auth/ttl', {
      method: 'POST', body: { hours: v }
    });
    setTtl(v);
    message.success('TTL: ' + v + 'h');
  };

  const toggle = async (v) => {
    await api('/api/triage-toggle', {
      method: 'POST', body: { enabled: v }
    });
    setTriage({ ...triage, auto_triage_enabled: v });
  };

  const cleanup = async () => {
    setLoading(true);
    await api('/api/cleanup', { method: 'POST' });
    setLoading(false);
    message.success('Done');
  };

  const savePrompt = async (v) => {
    setSavingPrompt(true);
    try {
      await api('/api/settings/prompt', {
        method: 'POST', body: { prompt: v.prompt }
      });
      message.success('Saved');
    } catch (e) { message.error(e.message); }
    setSavingPrompt(false);
  };

  const tabs = [
    { key: 'vllm', label: 'vLLM', children: <VllmTab /> }
  ];

  if (isAdmin) {
    tabs.unshift({
      key: 'ad', label: 'Active Directory',
      children: <AdSettingsTab authMode={authMode} />
    });
    tabs.push(
      { key: 'alerts', label: 'Alerts', children: <TelegramTab /> },
      {
        key: 'prompt', label: 'AI Prompt',
        children: (
          <Card title="Prompt" size="small" style={{ maxWidth: 800 }}>
            <Form form={promptForm} layout="vertical" onFinish={savePrompt}>
              <Form.Item name="prompt" label="Template">
                <Input.TextArea rows={12} />
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit"
                  loading={savingPrompt}>Save</Button>
              </Form.Item>
            </Form>
          </Card>
        )
      },
      {
        key: 'maintenance', label: 'Maintenance',
        children: (
          <Card title="Maintenance" size="small" style={{ maxWidth: 600 }}>
            <Popconfirm title="Delete old?" onConfirm={cleanup}>
              <Button danger icon={<DeleteOutlined />}
                loading={loading}>Delete old</Button>
            </Popconfirm>
            <div style={{ marginTop: 20 }}>
              <Text>Auto-triage:</Text>{' '}
              <Switch checked={triage.auto_triage_enabled} onChange={toggle} />
            </div>
            <div style={{ marginTop: 20 }}>
              <Text strong>Session Timeout:</Text>
              <Select value={ttl}
                style={{ width: 150, marginLeft: 12 }}
                onChange={changeTtl}
                options={[
                  { value: 0.5, label: '30 min' },
                  { value: 1, label: '1 hour' },
                  { value: 3, label: '3 hours' },
                  { value: 12, label: '12 hours' }
                ]} />
            </div>
          </Card>
        )
      }
    );
  }

  return (
    <Card title="Settings">
      {!isAdmin && (
        <Alert type="info" showIcon style={{ marginBottom: 16 }}
          message="Read-only: configuration is available to admins only" />
      )}
      <Tabs items={tabs} />
    </Card>
  );
}