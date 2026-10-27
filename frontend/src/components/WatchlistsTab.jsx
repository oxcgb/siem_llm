import React, { useState, useEffect } from 'react';
import {
  Alert, Button, Card, Form, Input, Popconfirm, Select,
  Space, Table, Tag, Typography, message
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import api from '../api';

const { Text } = Typography;

const LISTS = {
  elevated: {
    label: 'elevated',
    color: 'red',
    title: 'Elevated - never suppress',
    hint: 'VIPs, departing employees, accounts under investigation: ' +
          'personal/peer suppression is bypassed, every triggered rule stays in the score.'
  },
  benign: {
    label: 'benign',
    color: 'default',
    title: 'Benign - service accounts',
    hint: 'Monitoring/service accounts: noise rules (off-hours, geo, failures) are ' +
          'always suppressed. Absolutes (brute-force success) still alert.'
  }
};

export default function WatchlistsTab() {
  const [rows, setRows] = useState(null);
  const [adding, setAdding] = useState(false);
  const [form] = Form.useForm();

  const load = () =>
    api('/api/watchlists')
      .then(d => setRows(d?.watchlists || []))
      .catch(e => message.error(e.message));

  useEffect(() => { load(); }, []);

  const add = async (v) => {
    setAdding(true);
    try {
      const d = await api('/api/watchlists', {
        method: 'POST', body: v
      });
      setRows(d?.watchlists || []);
      form.resetFields();
      message.success(`${v.username} -> ${v.list_name}`);
    } catch (e) { message.error(e.message); }
    setAdding(false);
  };

  const remove = async (id) => {
    try {
      const d = await api(`/api/watchlists/${id}`, { method: 'DELETE' });
      setRows(d?.watchlists || []);
      message.success('Removed');
    } catch (e) { message.error(e.message); }
  };

  const columns = [
    { title: 'User', dataIndex: 'username', width: 200 },
    {
      title: 'List', dataIndex: 'list_name', width: 120,
      render: v => <Tag color={LISTS[v]?.color}>{v}</Tag>
    },
    { title: 'Note', dataIndex: 'note', ellipsis: true },
    {
      title: 'Added', dataIndex: 'created_at', width: 170,
      render: (v, r) =>
        <Text type="secondary">{v} {r.created_by ? `by ${r.created_by}` : ''}</Text>
    },
    {
      title: '', key: 'act', width: 60,
      render: (_, r) => (
        <Popconfirm title={`Remove ${r.username} from ${r.list_name}?`}
          onConfirm={() => remove(r.id)}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      )
    }
  ];

  return (
    <Card title="Watchlists" size="small" style={{ maxWidth: 800 }}>
      <Alert type="info" showIcon style={{ marginBottom: 16 }}
        message="Curated lists that change how the UEBA engine treats a user"
        description={
          <Space direction="vertical" size={2}>
            {Object.values(LISTS).map(l => (
              <Text key={l.label}>
                <Tag color={l.color} style={{ marginRight: 6 }}>{l.label}</Tag>
                {l.hint}
              </Text>
            ))}
            <Text type="secondary">
              Effects apply while UEBA is enabled (Settings - UEBA). Manual triage
              requests always return the user. Every change is audited.
            </Text>
          </Space>
        }
      />

      <Form form={form} layout="inline" onFinish={add}
        initialValues={{ list_name: 'elevated' }}
        style={{ marginBottom: 16 }}>
        <Form.Item name="list_name" rules={[{ required: true }]}>
          <Select style={{ width: 130 }}>
            {Object.values(LISTS).map(l => (
              <Select.Option key={l.label} value={l.label}>{l.label}</Select.Option>
            ))}
          </Select>
        </Form.Item>
        <Form.Item name="username"
          rules={[{ required: true, message: 'username required' }]}>
          <Input placeholder="username" style={{ width: 180 }} />
        </Form.Item>
        <Form.Item name="note">
          <Input placeholder="note (optional)" style={{ width: 220 }} />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit"
            loading={adding} icon={<PlusOutlined />}>
            Add
          </Button>
        </Form.Item>
      </Form>

      <Table dataSource={rows || []} columns={columns}
        rowKey="id" size="small" bordered
        pagination={rows && rows.length > 25 ? { pageSize: 25 } : false}
        loading={rows === null} />
    </Card>
  );
}
