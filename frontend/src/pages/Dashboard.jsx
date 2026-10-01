import React, {
  useState, useEffect
} from 'react';
import {
  Button, Card, Col,
  Progress, Row,
  Statistic, Switch, Alert,
  Table, Tag, Space,
  Typography, message
} from 'antd';
import {
  ReloadOutlined
} from '@ant-design/icons';
import api from '../api';
import { fmtTime } from '../time';

const { Text } = Typography;

export default function Dashboard() {
  const [stats, setStats] = useState({});
  const [summary, setSummary] = useState({
    datasources: 0,
    vpn_events: 0,
    ad_events: 0,
    rules: 0,
    recent_vpn: []
  });
  const [triage, setTriage] = useState({
    status: 'idle',
    auto_triage_enabled: true,
    message: ''
  });
  const [err, setErr] = useState(null);

  const loadSummary = () =>
    api('/api/stats/summary')
      .then(d => {
        setSummary(d);
        setErr(null);
      })
      .catch(e => {
        setErr(e.message);
        console.error(
          'summary:', e);
      });

  const loadTriage = () =>
    api('/api/triage-status')
      .then(setTriage)
      .catch(() => {});

  useEffect(() => {
    loadSummary();
    loadTriage();
    const f = () =>
      api('/api/system-stats')
        .then(setStats)
        .catch(() => {});
    f();
    const iv1 = setInterval(f, 5000);
    const iv2 =
      setInterval(loadTriage, 30000);
    return () => {
      clearInterval(iv1);
      clearInterval(iv2);
    };
  }, []);

  const toggle = async (v) => {
    await api(
      '/api/triage-toggle', {
      method: 'POST',
      body: { enabled: v }
    }).catch(() => {});
    setTriage({
      ...triage,
      auto_triage_enabled: v
    });
  };

  const vpnCols = [
    {
      title: 'Time',
      dataIndex: 'timestamp',
      width: 170,
      render: v => fmtTime(v)
    },
    {
      title: 'User',
      dataIndex: 'username'
    },
    {
      title: 'IP',
      dataIndex: 'src_ip'
    },
    {
      title: 'Action',
      dataIndex: 'action',
      render: v => (
        <Tag color={
          v === 'login_success'
            ? 'green' :
          v === 'login_failed'
            ? 'red' :
          'default'
        }>{v}</Tag>
      )
    }
  ];

  return (
    <div>
      {err && (
        <Alert
          type="error"
          message="API Error"
          description={err}
          style={{
            marginBottom: 20
          }}
        />
      )}
      <Row gutter={16}
        style={{
          marginBottom: 20
        }}>
        <Col span={8}>
          <Card>
            <div style={{
              textAlign: 'center'
            }}>
              <Progress
                type="dashboard"
                percent={
                  stats.cpu || 0
                }
                size={150}
                format={p => (
                  <span style={{
                    fontSize: 24,
                    fontWeight: 'bold'
                  }}>
                    {p}%
                  </span>
                )}
              />
              <div style={{
                marginTop: 10
              }}>
                <Text strong>
                  CPU Usage
                </Text>
              </div>
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <div style={{
              textAlign: 'center'
            }}>
              <Progress
                type="dashboard"
                percent={
                  stats.ram_total
                    ? Math.round(
                      (stats.ram_used /
                      stats.ram_total)
                      * 100)
                    : 0
                }
                size={150}
                format={() => (
                  <span style={{
                    fontSize: 15,
                    fontWeight: 'bold'
                  }}>
                    {stats.ram_used || 0}
                    {' / '}
                    {stats.ram_total || 0}
                    {' GB'}
                  </span>
                )}
              />
              <div style={{
                marginTop: 10
              }}>
                <Text strong>
                  Memory (RAM)
                </Text>
              </div>
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <div style={{
              textAlign: 'center'
            }}>
              <Progress
                type="dashboard"
                percent={
                  stats.gpu_total
                    ? Math.round(
                      (stats.gpu_used /
                      stats.gpu_total)
                      * 100)
                    : 0
                }
                size={150}
                format={() => (
                  <span style={{
                    fontSize: 15,
                    fontWeight: 'bold'
                  }}>
                    {stats.gpu_used || 0}
                    {' / '}
                    {stats.gpu_total || 0}
                    {' GB'}
                  </span>
                )}
              />
              <div style={{
                marginTop: 10
              }}>
                <Text strong>
                  GPU VRAM
                </Text>
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Data Sources"
              value={
                summary
                  .datasources || 0
              }
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="VPN Events"
              value={
                summary
                  .vpn_events || 0
              }
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="AD Events"
              value={
                summary
                  .ad_events || 0
              }
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Playbooks"
              value={
                summary.rules || 0
              }
            />
          </Card>
        </Col>
      </Row>

      <Card
        title="Auto-Triage"
        size="small"
        style={{
          marginTop: 20
        }}
        extra={
          <Switch
            checked={
              triage
                .auto_triage_enabled
            }
            onChange={toggle}
          />
        }
      >
        <Space>
          <Tag color={
            triage.status === 'running'
              ? 'processing' :
            triage.status === 'error'
              ? 'red' : 'green'
          }>
            {triage.status}
          </Tag>
          <Text>
            {triage.message || 'ok'}
          </Text>
          {triage.analyzed > 0 && (
            <Tag color="blue">
              {triage.analyzed}
              {' analyzed'}
            </Tag>
          )}
        </Space>
      </Card>

      <Card
        title="Recent VPN Events"
        style={{
          marginTop: 20
        }}
        extra={
          <Button
            icon={
              <ReloadOutlined />
            }
            onClick={
              loadSummary
            }
          >
            Refresh
          </Button>
        }
      >
        <Table
          dataSource={
            summary
              .recent_vpn || []
          }
          columns={vpnCols}
          rowKey="id"
          pagination={false}
          size="small"
        />
      </Card>
    </div>
  );
}
