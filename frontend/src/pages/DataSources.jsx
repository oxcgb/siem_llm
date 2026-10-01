import React, { useState, useEffect, useRef } from 'react';
import {
  Button, Card, Form, Input, Popconfirm,
  Row, Col, Select, Table, Tag, Modal,
  Space, Typography, message
} from 'antd';
import {
  CloudDownloadOutlined, EditOutlined,
  DeleteOutlined, ReloadOutlined
} from '@ant-design/icons';
import api from '../api';

const { Text } = Typography;

export default function DataSources() {
  const [ds, setDs] = useState([]);
  const [logTypes, setLogTypes] = useState([]);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [fetching, setFetching] = useState(false);
  const [fetchStatus, setFetchStatus] = useState(null);
  const pollRef = useRef(null);

  const [form] = Form.useForm();
  const [editForm] = Form.useForm();

  const load = () =>
    api('/api/datasources')
      .then(d => setDs(d || []))
      .catch(e => message.error(e.message));

  useEffect(() => {
    load();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const fetchNow = async () => {
    setFetching(true);
    try {
      await api('/api/fetch', { method: 'POST' });
      message.info('Fetching...');
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const d = await api('/api/fetch-status');
          setFetchStatus(d);
          if (d.status !== 'running') {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setFetching(false);
            if (d.status === 'done') {
              message.success(`Fetched: ${d.saved} new`);
              load();
            }
            if (d.status === 'error') {
              message.error('Fetch failed: ' + d.message);
            }
          }
        } catch { /* keep polling */ }
      }, 2000);
    } catch (e) {
      message.error(e.message);
      setFetching(false);
    }
  };

  const add = async (v) => {
    const payload = {
      query: v.query || '',
      log_types: v.log_types || []
    };
    const body = {
      name: v.name || 'Unnamed',
      api_url: v.api_url,
      payload_json: JSON.stringify(payload, null, 2)
    };
    if (v.auth_header) body.auth_header = v.auth_header;
    try {
      await api('/api/datasources', { method: 'POST', body });
      form.resetFields();
      load();
      message.success('Added');
    } catch (e) { message.error(e.message); }
  };

  const openEdit = (r) => {
    setEditing(r);
    let d = {};
    try { d = JSON.parse(r.payload_json || '{}'); } catch {}
    editForm.setFieldsValue({
      name: r.name, api_url: r.api_url,
      auth_header: '',
      query: d.query || '',
      log_types: d.log_types || []
    });
    setModal(true);
  };

  const update = async (v) => {
    const payload = {
      query: v.query || '',
      log_types: v.log_types || []
    };
    const body = {
      name: v.name, api_url: v.api_url,
      payload_json: JSON.stringify(payload, null, 2)
    };
    if (v.auth_header) body.auth_header = v.auth_header;
    try {
      await api('/api/datasources/' + editing.id,
        { method: 'PUT', body });
      setModal(false);
      load();
      message.success('Updated');
    } catch (e) { message.error(e.message); }
  };

  const del = async (id) => {
    try {
      await api('/api/datasources/' + id,
        { method: 'DELETE' });
      load();
    } catch (e) { message.error(e.message); }
  };

  const typeOptions =
    logTypes.length > 0
      ? logTypes.map(t => ({ value: t, label: t }))
      : ['Windows', 'Unix', 'VPN',
         'Cisco Device', 'ADAP']
        .map(v => ({ value: v, label: v }));

  const cols = [
    { title: 'Name', dataIndex: 'name', width: 150 },
    { title: 'API URL', dataIndex: 'api_url', ellipsis: true },
    { title: 'Token', dataIndex: 'auth_header', width: 120,
      render: (v, r) => {
        if (r.token_invalid) return <Tag color="red">invalid</Tag>;
        return v
          ? <Tag color="green">{v}</Tag>
          : <Tag>none</Tag>;
      } },
    { title: 'Payload', dataIndex: 'payload_json',
      ellipsis: true,
      render: v => (
        <code style={{ fontSize: 11 }}>
          {(v || '').substring(0, 60)}…
        </code>
      ) },
    { title: 'Actions', key: 'act', width: 180,
      render: (_, r) => (
        <Space>
          <Button size="small"
            icon={<EditOutlined />}
            onClick={() => openEdit(r)}>Edit</Button>
          <Popconfirm title="Delete?"
            onConfirm={() => del(r.id)}>
            <Button danger size="small"
              icon={<DeleteOutlined />}>Del</Button>
          </Popconfirm>
        </Space>
      ) }
  ];

  return (
    <div>
      <Card title="Add Data Source"
        style={{ marginBottom: 20 }}>
        <Form form={form} layout="vertical" onFinish={add}>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="name" label="Name">
                <Input placeholder="SIEM" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="api_url" label="API URL"
                rules={[{ required: true }]}>
                <Input placeholder="https://..." />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="auth_header" label="Token">
                <Input.Password />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="query" label="Query"
                initialValue="*113005* OR *113039*">
                <Input />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="log_types" label="Types"
                initialValue={['Cisco Device']}>
                <Select mode="multiple"
                  options={typeOptions} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item>
            <Button type="primary" htmlType="submit">Save</Button>
          </Form.Item>
        </Form>
      </Card>

      <Card title="Sources"
        extra={
          <Space>
            {fetchStatus && fetchStatus.status === 'running' && (
              <Text type="secondary">fetching…</Text>
            )}
            <Button icon={<CloudDownloadOutlined />}
              loading={fetching} onClick={fetchNow}>
              Fetch Now</Button>
            <Button icon={<ReloadOutlined />}
              onClick={load}>Refresh</Button>
          </Space>
        }>
        <Table dataSource={ds} columns={cols}
          rowKey="id" pagination={false} />
      </Card>

      <Modal title="Edit Source" open={modal}
        onCancel={() => setModal(false)}
        onOk={() => editForm.submit()} width={700}>
        <Form form={editForm} layout="vertical"
          onFinish={update}>
          <Form.Item name="name" label="Name">
            <Input />
          </Form.Item>
          <Form.Item name="api_url" label="API URL"
            rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="auth_header"
            label="Token (empty = keep)">
            <Input.Password placeholder="••••••" />
          </Form.Item>
          <Form.Item name="query" label="Query">
            <Input />
          </Form.Item>
          <Form.Item name="log_types" label="Types">
            <Select mode="multiple" options={typeOptions} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}