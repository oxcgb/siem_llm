import React, {
  useState, useEffect
} from 'react';
import {
  Alert, Button, Card,
  Form, Input, Select,
  Space, Switch,
  Typography, message
} from 'antd';
import api from '../api';

const { Text } = Typography;

export default function TelegramTab() {
  const [form] = Form.useForm();
  const [saving, setSaving] =
    useState(false);
  const [testing, setTesting] =
    useState(false);
  const [testRes, setTestRes] =
    useState(null);

  useEffect(() => {
    api('/api/telegram/config')
      .then(cfg => {
        form.setFieldsValue({
          ...cfg,
          bot_token: ''
        });
      })
      .catch(e =>
        message.error(
          e.message));
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const v =
        form.getFieldsValue();
      await api(
        '/api/telegram/config', {
        method: 'POST',
        body: v
      });
      message.success(
        'Saved');
    } catch (e) {
      message.error(
        e.message);
    }
    setSaving(false);
  };

  const test = async () => {
    setTesting(true);
    setTestRes(null);
    try {
      const v =
        form.getFieldsValue();
      const r = await api(
        '/api/telegram/test', {
        method: 'POST',
        body: v
      });
      setTestRes(r);
    } catch (e) {
      setTestRes({
        ok: false,
        message: e.message
      });
    }
    setTesting(false);
  };

  return (
    <Card
      title="Telegram Alerts"
      size="small"
      style={{
        maxWidth: 700
      }}
    >
      <Alert
        style={{
          marginBottom: 16
        }}
        type="info"
        showIcon
        message="Alerts"
        description={
          'Auto-triage: ' +
          'severity >= medium'
        }
      />
      <Form
        form={form}
        layout="vertical"
      >
        <Form.Item
          name="enabled"
          label="Enable"
          valuePropName=
            "checked"
        >
          <Switch />
        </Form.Item>
        <Form.Item
          name="bot_token"
          label="Bot Token"
        >
          <Input.Password
            placeholder="••••••"
          />
        </Form.Item>
        <Form.Item
          name="chat_id"
          label="Chat ID"
        >
          <Input
            placeholder="123456"
          />
        </Form.Item>
        <Form.Item
          name="min_severity"
          label="Min Severity"
        >
          <Select
            options={[
              { value: 'low',
                label: 'Low' },
              { value: 'medium',
                label: 'Medium' },
              { value: 'high',
                label: 'High' }
            ]}
          />
        </Form.Item>
        <Space>
          <Button
            onClick={test}
            loading={testing}
          >
            Test
          </Button>
          <Button
            type="primary"
            onClick={save}
            loading={saving}
          >
            Save
          </Button>
        </Space>
        {testRes && (
          <Alert
            style={{
              marginTop: 16
            }}
            type={testRes.ok
              ? 'success'
              : 'error'}
            showIcon
            message={
              testRes.ok
                ? 'Sent!'
                : 'Error'
            }
            description={
              testRes.message ||
              testRes.msg
            }
          />
        )}
      </Form>
    </Card>
  );
}
