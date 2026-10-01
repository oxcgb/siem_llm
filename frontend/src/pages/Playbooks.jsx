import React, { useState, useEffect, useRef } from 'react';
import {
  Alert, Button, Card, Descriptions, Drawer, Form,
  Input, InputNumber, Modal, Popconfirm, Radio,
  Row, Col, Select, Space, Table, Tag,
  Typography, message
} from 'antd';
import {
  PlayCircleOutlined, EditOutlined,
  DeleteOutlined, ReloadOutlined
} from '@ant-design/icons';
import api from '../api';
import { fmtTime } from '../time';

const { Text } = Typography;

export default function Playbooks() {
  const [rules, setRules] = useState([]);
  const [runs, setRuns] = useState([]);
  const [running, setRunning] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [verdictFilter, setVerdictFilter] = useState('all');
  const pollRef = useRef(null);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState(null);

  const loadRules = () =>
    api('/api/rules').then(d => setRules(d || [])).catch(() => {});
  const loadRuns = () =>
    api('/api/playbook-runs')
      .then(d => setRuns(d?.runs || []))
      .catch(() => {});

  useEffect(() => {
    loadRules();
    loadRuns();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const startPolling = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const d = await api('/api/report-status');
        if (d.status !== 'running') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setRunning(null);
          loadRuns();
          if (d.status === 'done') {
            message.success(`Done: ${d.analyzed}/${d.total} analyzed`);
            if (d.run_id) openRun(d.run_id);
          } else if (d.status === 'error') {
            message.error('Failed: ' + (d.message || '?'));
          }
        }
      } catch { /* keep polling */ }
    }, 2000);
  };

  const run = async (id) => {
    setRunning(id);
    try {
      await api('/api/correlate/' + id, { method: 'POST' });
      message.info('Running...');
      startPolling();
    } catch (e) {
      message.error(e.message);
      setRunning(null);
    }
  };

  const openRun = async (id) => {
    setDetailLoading(true);
    setVerdictFilter('all');
    try {
      setDetail(await api('/api/playbook-runs/' + id));
    } catch (e) { message.error(e.message); }
    setDetailLoading(false);
  };

  const add = async (v) => {
    try {
      await api('/api/rules', {
        method: 'POST',
        body: {
          ...v, depth: v.depth || 'standard',
          window_hours: v.window_hours || 24
        }
      });
      form.resetFields();
      loadRules();
      message.success('Created');
    } catch (e) { message.error(e.message); }
  };

  const edit = (r) => {
    setEditing(r);
    editForm.setFieldsValue({
      name: r.name, description: r.description,
      prompt: r.prompt, depth: r.depth || 'standard',
      window_hours: r.window_hours || 24
    });
    setModal(true);
  };

  const update = async (v) => {
    try {
      await api('/api/rules/' + editing.id, {
        method: 'PUT',
        body: {
          ...v, depth: v.depth || 'standard',
          window_hours: v.window_hours || 24
        }
      });
      setModal(false);
      loadRules();
      message.success('Updated');
    } catch (e) { message.error(e.message); }
  };

  const del = async (id) => {
    try {
      await api('/api/rules/' + id, { method: 'DELETE' });
      loadRules();
    } catch (e) { message.error(e.message); }
  };

  const ruleCols = [
    { title: 'Name', dataIndex: 'name' },
    { title: 'Depth', dataIndex: 'depth', width: 90,
      render: v => (
        <Tag color={v === 'quick' ? 'blue' :
          v === 'deep' ? 'red' : 'green'}>{v || 'std'}</Tag>
      ) },
    { title: 'Window', dataIndex: 'window_hours', width: 90,
      render: v => (v || 24) + 'h' },
    { title: 'Prompt', dataIndex: 'prompt', ellipsis: true },
    { title: '', width: 220, render: (_, r) => (
      <Space>
        <Button type="primary" size="small"
          icon={<PlayCircleOutlined />}
          loading={running === r.id}
          disabled={!!running && running !== r.id}
          onClick={() => run(r.id)}>Run</Button>
        <Button size="small" icon={<EditOutlined />}
          onClick={() => edit(r)} />
        <Popconfirm title="Delete?"
          onConfirm={() => del(r.id)}>
          <Button danger size="small"
            icon={<DeleteOutlined />} />
        </Popconfirm>
      </Space>
    ) }
  ];

  const runCols = [
    { title: '#', dataIndex: 'id', width: 60 },
    { title: 'Playbook', dataIndex: 'rule_name' },
    { title: 'Depth', dataIndex: 'depth', width: 80 },
    { title: 'Status', dataIndex: 'status', width: 90,
      render: v => (
        <Tag color={v === 'done' ? 'green' :
          v === 'error' ? 'red' : 'processing'}>{v}</Tag>
      ) },
    { title: 'Total', dataIndex: 'total', width: 70 },
    { title: 'Analyzed', dataIndex: 'analyzed', width: 85 },
    { title: 'Started', dataIndex: 'started_at', width: 160,
      render: v => fmtTime(v) },
    { title: '', width: 90, render: (_, r) => (
      <Button size="small" onClick={() => openRun(r.id)}>
        View</Button>
    ) }
  ];

  const events = detail?.events || [];
  const filteredEvents = verdictFilter === 'all'
    ? events
    : events.filter(e => e.verdict === verdictFilter);

  const evtCols = [
    { title: 'Time', dataIndex: 'timestamp', width: 150,
      render: v => fmtTime(v) },
    { title: 'Src', dataIndex: 'source_type', width: 60,
      render: v => (
        <Tag color={v === 'VPN' ? 'green' : 'geekblue'}>{v}</Tag>
      ) },
    { title: 'User', dataIndex: 'username', width: 120 },
    { title: 'IP', dataIndex: 'src_ip', width: 130 },
    { title: 'Action', dataIndex: 'action', width: 120 },
    { title: 'Verdict', dataIndex: 'verdict', width: 110,
      render: v => {
        const c = v === 'malicious' ? 'red' :
          v === 'suspicious' ? 'orange' :
          v === 'benign' ? 'green' : 'default';
        return <Tag color={c}>{v}</Tag>;
      } },
    { title: 'Risk', dataIndex: 'risk_score', width: 60 },
    { title: 'Reason', dataIndex: 'reason', ellipsis: true }
  ];

  return (
    <div>
      <Card title="Create Playbook"
        style={{ marginBottom: 20 }}>
        <Form form={form} layout="vertical" onFinish={add}>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="name" label="Name">
                <Input placeholder="Off-hours review" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="depth" label="Depth"
                initialValue="standard">
                <Radio.Group>
                  <Radio.Button value="quick">Quick</Radio.Button>
                  <Radio.Button value="standard">Std</Radio.Button>
                  <Radio.Button value="deep">Deep</Radio.Button>
                </Radio.Group>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="window_hours" label="Window (hours)"
                initialValue={24}
                rules={[{ required: true }]}>
                <InputNumber min={1} max={168}
                  style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="prompt" label="Prompt">
            <Input.TextArea rows={3}
              placeholder="Find accounts with suspicious activity..." />
          </Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Card>

      <Card title="Playbooks" style={{ marginBottom: 20 }}
        extra={
          <Button icon={<ReloadOutlined />}
            onClick={() => { loadRules(); loadRuns(); }}>
            Refresh</Button>
        }>
        <Table dataSource={rules} columns={ruleCols}
          rowKey="id" pagination={false} size="small" />
      </Card>

      <Card title="Recent Runs">
        <Table dataSource={runs} columns={runCols}
          rowKey="id" size="small"
          pagination={{ pageSize: 10 }} />
      </Card>

      <Modal title="Edit" open={modal}
        onCancel={() => setModal(false)}
        onOk={() => editForm.submit()}>
        <Form form={editForm} layout="vertical" onFinish={update}>
          <Form.Item name="name" label="Name">
            <Input />
          </Form.Item>
          <Form.Item name="prompt" label="Prompt">
            <Input.TextArea rows={4} />
          </Form.Item>
          <Form.Item name="depth" label="Depth">
            <Radio.Group>
              <Radio.Button value="quick">Quick</Radio.Button>
              <Radio.Button value="standard">Std</Radio.Button>
              <Radio.Button value="deep">Deep</Radio.Button>
            </Radio.Group>
          </Form.Item>
          <Form.Item name="window_hours" label="Window (hours)"
            rules={[{ required: true }]}>
            <InputNumber min={1} max={168}
              style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title={detail
          ? `Run #${detail.id} — ${detail.rule_name}` : 'Run'}
        width="80%" open={!!detail}
        onClose={() => setDetail(null)}>
        {detail && (
          <>
            <Descriptions size="small" bordered column={4}
              style={{ marginBottom: 16 }}>
              <Descriptions.Item label="Status">
                <Tag color={detail.status === 'done' ? 'green' :
                  detail.status === 'error' ? 'red' : 'processing'}>
                  {detail.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Depth">
                {detail.depth}</Descriptions.Item>
              <Descriptions.Item label="Total">
                {detail.total}</Descriptions.Item>
              <Descriptions.Item label="Analyzed">
                {detail.analyzed}</Descriptions.Item>
            </Descriptions>
            {detail.error && (
              <Alert type="error" showIcon style={{ marginBottom: 16 }}
                message={detail.error} />
            )}
            <Space style={{ marginBottom: 12 }}>
              <Select value={verdictFilter}
                onChange={setVerdictFilter} style={{ width: 170 }}>
                <Select.Option value="all">All verdicts</Select.Option>
                <Select.Option value="malicious">malicious</Select.Option>
                <Select.Option value="suspicious">suspicious</Select.Option>
                <Select.Option value="benign">benign</Select.Option>
                <Select.Option value="not_analyzed">not_analyzed</Select.Option>
              </Select>
              <Text type="secondary">
                {filteredEvents.length} / {events.length} events
              </Text>
            </Space>
            <Table dataSource={filteredEvents} columns={evtCols}
              rowKey={r => r.source_type + '-' + r.id}
              size="small" pagination={{ pageSize: 50 }}
              loading={detailLoading} />
          </>
        )}
      </Drawer>
    </div>
  );
}