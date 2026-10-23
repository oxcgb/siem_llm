import React, { useState, useEffect, useRef } from 'react';
import {
  Alert, Button, Card, Col, Descriptions, Input, Row,
  Select, Space, Statistic, Switch, Table, Tag, Typography, message
} from 'antd';
import { ReloadOutlined, BugOutlined } from '@ant-design/icons';
import api from '../api';
import { fmtTime, TZ_LABEL } from '../time';

const { Text } = Typography;

const HOURS = { '1h': 1, '8h': 8, '24h': 24, '7d': 168 };
const RATIO_TIP = 'Во сколько раз средняя скорость дропов превысила лимит ASA (avg/max). 2x — заметно, 5x+ — критично.';

export default function NetworkPage() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [q, setQ] = useState('');
  const [hours, setHours] = useState('24h');
  const [action, setAction] = useState('');
  const [summary, setSummary] = useState(null);
  const [busy, setBusy] = useState(false);
  const [auto, setAuto] = useState(true);
  const hoursRef = useRef(hours);
  hoursRef.current = hours;

  const loadEvents = async (p = page, ps = pageSize, query = q, h = hours, a = action) => {
    const params = new URLSearchParams({
      limit: ps, offset: (p - 1) * ps, hours: HOURS[h]
    });
    if (query) params.set('q', query);
    if (a) params.set('action', a);
    try {
      const d = await api('/api/network-events?' + params);
      setEvents(d.events || []);
      setTotal(d.total || 0);
      setPage(p); setPageSize(ps);
    } catch (e) { console.error(e); }
  };

  const loadSummary = async (h = hours) => {
    try {
      setSummary(await api('/api/network-summary?hours=' + HOURS[h]));
    } catch (e) { console.error(e); }
  };

  useEffect(() => { loadEvents(1, 50, '', '24h', ''); loadSummary('24h'); }, []);

  useEffect(() => {
    if (!auto) return undefined;
    const iv = setInterval(() => {
      loadSummary(hoursRef.current);
      loadEvents();
    }, 60000);
    return () => clearInterval(iv);
  }, [auto]);

  const analyze = async () => {
    setBusy(true);
    message.loading({ content: 'Analyzing network aggregates...', key: 'net', duration: 0 });
    try {
      await api('/api/network-analyze', { method: 'POST', timeout: 300000 });
      message.success({ content: 'Done — check Playbook runs', key: 'net' });
    } catch (e) {
      message.error({ content: 'Failed: ' + e.message, key: 'net' });
    }
    setBusy(false);
  };

  const ratioTag = v => v != null
    ? <Tag color={v >= 5 ? 'red' : v >= 2 ? 'orange' : 'green'}>{v}×</Tag>
    : <Text type="secondary">—</Text>;

  const isDropRate = r => r.action === 'drop_rate_exceeded';
  const isFlow = r => ['acl_denied', 'deny_no_conn', 'denied'].includes(r.action);

  const actionColor = {
    'drop_rate_exceeded': 'orange', 'denied': 'red',
    'acl_denied': 'red', 'deny_no_conn': 'volcano', 'network_other': 'default'
  };

  const anyDropRate = events.some(r => isDropRate(r));
  const anyFlow = events.some(r => isFlow(r));

  const timeCol = {
    title: 'Time (' + TZ_LABEL + ')', dataIndex: 'timestamp', width: 155,
    render: v => fmtTime(v)
  };
  const actionCol = {
    title: 'Action', dataIndex: 'action', width: 145,
    render: v => <Tag color={actionColor[v] || 'default'}>{v}</Tag>
  };
  const hitsCol = {
    title: 'Hits', dataIndex: 'event_count', width: 70,
    render: v => (v != null && v > 1) ? <Tag color="purple">×{v}</Tag> : (v ?? '—')
  };

  const subjectCol = {
    title: 'Subject', dataIndex: 'subject', width: 150,
    render: (v, r) => isDropRate(r)
      ? <Space size={4}>
          <Text strong>{v}</Text>
          <Tag color={r.subject_kind === 'category' ? 'purple' : 'geekblue'}>
            {r.subject_kind === 'category' ? 'ASA system' : 'drop target'}
          </Tag>
        </Space>
      : <Text type="secondary">{v}</Text>
  };

  const srcCol = {
    title: 'Src', dataIndex: 'src_ip', width: 135,
    render: (v, r) => isFlow(r)
      ? ((v && v !== 'N/A')
        ? <span>
            <Text strong>{v}</Text>
            {r.src_port && r.src_port !== 'N/A'
              ? <Text type="secondary">:{r.src_port}</Text> : null}
          </span>
        : '—')
      : <Text type="secondary">—</Text>
  };

  const dstCol = {
    title: '→ Dst', dataIndex: 'dst_ip', width: 135,
    render: (v, r) => isFlow(r)
      ? ((v && v !== 'N/A')
        ? <span>
            <Text strong type="danger">{v}</Text>
            {r.dst_port && r.dst_port !== 'N/A'
              ? <Text type="secondary">:{r.dst_port}</Text> : null}
          </span>
        : '—')
      : <Text type="secondary">—</Text>
  };

  const protoCol = {
    title: 'Proto', dataIndex: 'protocol', width: 65,
    render: v => (v && v !== 'N/A') ? v : '—'
  };

  const aclCol = {
    title: 'ACL / Flags / If', key: 'aclflags', width: 185,
    render: (_, r) => {
      if (!isFlow(r)) return <Text type="secondary">—</Text>;
      const parts = [];
      if (r.acl && r.acl !== 'N/A') parts.push(<Tag key="a" color="cyan">{r.acl}</Tag>);
      if (r.flags && r.flags !== 'N/A') parts.push(<Tag key="f">{r.flags}</Tag>);
      if (r.src_if && r.src_if !== 'N/A') parts.push(<Tag key="i">{r.src_if}</Tag>);
      return parts.length ? <Space size={4} wrap>{parts}</Space> : '—';
    }
  };

  const burstCol = {
    title: 'Burst (cur/max)', key: 'burst', width: 110,
    render: (_, r) => (isDropRate(r) && r.burst_rate != null)
      ? `${r.burst_rate}/${r.burst_max}` : <Text type="secondary">—</Text>
  };
  const avgCol = {
    title: 'Avg (cur/max)', key: 'avg', width: 105,
    render: (_, r) => (isDropRate(r) && r.avg_rate != null)
      ? `${r.avg_rate}/${r.avg_max}` : <Text type="secondary">—</Text>
  };
  const ratioCol = {
    title: <span title={RATIO_TIP}>Превыш.</span>,
    dataIndex: 'avg_ratio', width: 80, render: ratioTag
  };
  const cumCol = {
    title: 'Cumulative', dataIndex: 'cumulative', width: 95,
    render: (_, r) => (isDropRate(r) && r.cumulative != null)
      ? r.cumulative.toLocaleString() : <Text type="secondary">—</Text>
  };

  const cols = [
    timeCol,
    actionCol,
    ...(anyDropRate ? [subjectCol] : []),
    ...(anyFlow ? [srcCol, dstCol, protoCol, aclCol] : []),
    ...(anyDropRate ? [burstCol, avgCol, ratioCol, cumCol] : []),
    hitsCol,
  ];

  const statCols = [
    { title: 'Rows', dataIndex: 'n', width: 65 },
    { title: 'Hits', dataIndex: 'hits', width: 75,
      render: v => (v != null ? v : '—') },
    { title: <span title={RATIO_TIP}>Превышение</span>,
      dataIndex: 'max_ratio', width: 105, render: ratioTag },
    { title: 'Avg cur/max', key: 'avg', width: 105,
      render: (_, r) => (r.avg_rate != null && r.avg_max != null)
        ? `${r.avg_rate}/${r.avg_max}` : '—' },
    { title: 'Cumulative', dataIndex: 'max_cumulative', width: 105,
      render: v => v != null ? v.toLocaleString() : '—' },
    { title: 'Last seen (' + TZ_LABEL + ')', dataIndex: 'last_seen', width: 160,
      render: v => fmtTime(v) },
  ];

  return (
    <div>
      {summary && summary.bruteforce && summary.bruteforce.length > 0 && (
        <Card size="small" style={{ marginBottom: 20, borderTop: '3px solid #a8071a', background: '#fff1f0' }}
          title={<Text strong type="danger">Брутфорс VPN — публичные IP подбирают пароли</Text>}>
          <Alert type="error" showIcon style={{ marginBottom: 12 }}
            message="Внешние IP с ≥10 неудачными попытками входа за окно. Проверьте успешные входы и закройте доступ на ASA." />
          <Table dataSource={summary.bruteforce} size="small" pagination={false}
            rowKey="src_ip"
            columns={[
              { title: 'IP атакующего', dataIndex: 'src_ip', width: 150,
                render: v => <Text strong copyable>{v}</Text> },
              { title: 'Geo', dataIndex: 'geo', width: 190 },
              { title: 'Попыток', dataIndex: 'attempts', width: 100,
                render: v => <Tag color="red">{v}</Tag> },
              { title: 'Имён', dataIndex: 'uniq_names', width: 80,
                render: v => <Tag color={v > 1 ? 'orange' : 'default'}>{v}</Tag> },
              { title: 'First seen (' + TZ_LABEL + ')', dataIndex: 'first_seen', width: 165,
                render: v => fmtTime(v) },
              { title: 'Last seen (' + TZ_LABEL + ')', dataIndex: 'last_seen', width: 165,
                render: v => fmtTime(v) },
            ]} />
        </Card>
      )}

      {summary && summary.external && summary.external.length > 0 && (
        <Card size="small" style={{ marginBottom: 20, borderTop: '3px solid #ff4d4f' }}
          title={<Text strong type="danger">Внешние атакующие (rate) — публичные IP в drop-rate</Text>}>
          <Alert type="error" showIcon style={{ marginBottom: 12 }}
            message="ASA дропает трафик этих IP сверх лимитов (threat detection)." />
          <Table dataSource={summary.external} size="small" pagination={false}
            rowKey="subject"
            columns={[
              { title: 'IP', dataIndex: 'subject', width: 145,
                render: v => <Text strong copyable>{v}</Text> },
              { title: 'Geo', dataIndex: 'geo', width: 190 },
              ...statCols,
            ]} />
        </Card>
      )}

      {summary && summary.external_flows && summary.external_flows.length > 0 && (
        <Card size="small" style={{ marginBottom: 20, borderTop: '3px solid #cf1322' }}
          title={<Text strong type="danger">Внешние по deny-потокам — кто долбится и получает отказ</Text>}>
          <Alert type="warning" showIcon style={{ marginBottom: 12 }}
            message="Публичные источники запрещённых соединений. ≥3 разных портов = вероятный сканер." />
          <Table dataSource={summary.external_flows} size="small" pagination={false}
            rowKey="src_ip"
            columns={[
              { title: 'IP', dataIndex: 'src_ip', width: 145,
                render: (v, r) => <Space size={6}>
                  <Text strong copyable>{v}</Text>
                  {r.scanner && <Tag color="red">сканер</Tag>}
                </Space> },
              { title: 'Geo', dataIndex: 'geo', width: 190 },
              { title: 'Rows', dataIndex: 'n', width: 65 },
              { title: 'Hits', dataIndex: 'hits', width: 75 },
              { title: 'Цели', dataIndex: 'uniq_dst', width: 75,
                render: v => <Tag color={v > 1 ? 'orange' : 'default'}>{v}</Tag> },
              { title: 'Порты', dataIndex: 'uniq_ports', width: 75,
                render: v => <Tag color={v >= 3 ? 'red' : v > 1 ? 'orange' : 'default'}>{v}</Tag> },
              { title: 'Last seen (' + TZ_LABEL + ')', dataIndex: 'last_seen', width: 160,
                render: v => fmtTime(v) },
            ]} />
        </Card>
      )}

      {summary && summary.outbound && summary.outbound.length > 0 && (
        <Card size="small" style={{ marginBottom: 20, borderTop: '3px solid #faad14' }}
          title={<Text strong type="warning">Исходящие deny — внутренние хосты ломятся наружу</Text>}>
          <Alert type="warning" showIcon style={{ marginBottom: 12 }}
            message="Внутренние источники, чьи исходящие соединения отклоняет ACL. Нестандартные порты + повторяющиеся dst — кандидаты на C2." />
          <Table dataSource={summary.outbound} size="small" pagination={false}
            rowKey={r => r.src_ip + '-' + r.dst_ip + '-' + r.dst_port}
            columns={[
              { title: 'Src (внутр.)', dataIndex: 'src_ip', width: 130,
                render: v => <Text strong>{v}</Text> },
              { title: '→ Dst (внешн.)', dataIndex: 'dst_ip', width: 140,
                render: v => <Text strong type="danger">{v}</Text> },
              { title: 'Port', dataIndex: 'dst_port', width: 80,
                render: v => <Tag color="orange">{v}</Tag> },
              { title: 'Proto', dataIndex: 'protocol', width: 70 },
              { title: 'Rows', dataIndex: 'n', width: 70 },
              { title: 'Hits', dataIndex: 'hits', width: 80 },
              { title: 'Last seen (' + TZ_LABEL + ')', dataIndex: 'last_seen', width: 160,
                render: v => fmtTime(v) },
            ]} />
        </Card>
      )}

      {summary && summary.categories && summary.categories.length > 0 && (
        <Card title="Системные категории ASA (threat detection)" size="small"
          style={{ marginBottom: 20 }}>
          <Table dataSource={summary.categories} size="small" pagination={false}
            rowKey="subject"
            columns={[
              { title: 'Категория', dataIndex: 'subject', width: 145,
                render: v => <Tag color="purple">{v}</Tag> },
              ...statCols,
            ]} />
        </Card>
      )}

      {summary && (
        <Row gutter={16} style={{ marginBottom: 20 }}>
          {summary.actions.map(a => (
            <Col key={a.action} span={6}>
              <Card size="small">
                <Statistic title={a.action}
                  value={a.total_hits || a.n}
                  suffix={a.n !== a.total_hits && a.total_hits ? ` hits / ${a.n} rows` : ''} />
              </Card>
            </Col>
          ))}
        </Row>
      )}

      {summary && summary.internal && summary.internal.length > 0 && (
        <Card title="Внутренние субъекты (drop rate exceeded)" size="small"
          style={{ marginBottom: 20 }}>
          <Table dataSource={summary.internal} size="small" pagination={false}
            rowKey="subject"
            columns={[
              { title: 'IP', dataIndex: 'subject', width: 145,
                render: v => <Text strong>{v}</Text> },
              ...statCols,
            ]} />
        </Card>
      )}

      <Card title="Network Events"
        extra={
          <Space>
            <Text type="secondary">auto</Text>
            <Switch size="small" checked={auto} onChange={setAuto} />
            <Input.Search placeholder="Subject / IP / ACL" style={{ width: 170 }}
              onSearch={v => { setQ(v); loadEvents(1, pageSize, v, hours, action); }} />
            <Select value={action} style={{ width: 175 }} allowClear
              placeholder="Action"
              onChange={v => { setAction(v || ''); loadEvents(1, pageSize, q, hours, v || ''); }}
              options={[
                { value: 'drop_rate_exceeded', label: 'drop rate exceeded' },
                { value: 'acl_denied', label: 'ACL denied (flow)' },
                { value: 'deny_no_conn', label: 'deny no-conn (RST)' },
                { value: 'denied', label: 'denied IP' },
              ]} />
            <Select value={hours} style={{ width: 105 }}
              onChange={v => { setHours(v); loadEvents(1, pageSize, q, v, action); loadSummary(v); }}>
              {Object.keys(HOURS).map(k =>
                <Select.Option key={k} value={k}>Last {k}</Select.Option>)}
            </Select>
            <Button icon={<BugOutlined />} loading={busy} onClick={analyze}>
              AI Analyze
            </Button>
            <Button icon={<ReloadOutlined />}
              onClick={() => { loadEvents(); loadSummary(); }}>Refresh</Button>
          </Space>
        }>
        <Table dataSource={events} columns={cols} rowKey="id" size="small"
          scroll={{ x: 'max-content' }}
          pagination={{ current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => loadEvents(p, ps) }}
          expandable={{
            expandedRowRender: r => (
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label="Raw">
                  <Text code>{r.raw_event || '—'}</Text>
                </Descriptions.Item>
              </Descriptions>
            ),
            rowExpandable: r => !!r.raw_event
          }} />
      </Card>
    </div>
  );
}
