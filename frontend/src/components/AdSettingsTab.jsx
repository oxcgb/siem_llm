import React, {
  useState, useEffect
} from 'react';
import {
  Alert, Button, Card,
  Checkbox, Form, Input,
  Row, Col, Select,
  Space, Switch, Tag,
  Typography, message,
  Modal, Descriptions
} from 'antd';
import api from '../api';

const { Text } = Typography;

export default function AdSettingsTab({
  authMode
}) {
  const [form] = Form.useForm();
  const [saving, setSaving] =
    useState(false);
  const [testing, setTesting] =
    useState(false);
  const [testRes, setTestRes] =
    useState(null);
  const [searchQ, setSearchQ] =
    useState('');
  const [searchRes, setSearchRes] =
    useState(null);
  const [searching, setSearching] =
    useState(false);

  useEffect(() => {
    api('/api/auth/ldap-config')
      .then(cfg => {
        form.setFieldsValue({
          ...cfg,
          bind_password: ''
        });
      })
      .catch(e =>
        message.error(
          e.message));
  }, []);

  const collect = () => {
    const v =
      form.getFieldsValue();
    return {
      ...v,
      port: parseInt(
        v.port, 10) || 389
    };
  };

  const save = async () => {
    setSaving(true);
    try {
      await api(
        '/api/auth/ldap-config', {
        method: 'POST',
        body: collect()
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
      setTestRes(
        await api(
          '/api/auth/ldap-test', {
          method: 'POST',
          body: collect()
        }));
    } catch (e) {
      setTestRes({
        ok: false,
        message: e.message
      });
    }
    setTesting(false);
  };

  const userSearch = async () => {
    const q =
      searchQ.trim();
    if (q.length < 2) {
      return;
    }
    setSearching(true);
    setSearchRes(null);
    try {
      const r = await api(
        '/api/auth/ldap-search', {
        method: 'POST',
        body: { query: q }
      });
      setSearchRes(r);
    } catch (e) {
      setSearchRes({
        ok: false,
        message: e.message
      });
    }
    setSearching(false);
  };

  const inspect = async (u) => {
    try {
      const r = await api(
        '/api/auth/ldap-inspect', {
        method: 'POST',
        body: {
          username: u
        }
      });
      Modal.info({
        title: r.found
          ? 'User: ' +
            r.username
          : 'Not found',
        width: 640,
        content: (
          <Descriptions
            column={1}
            size="small"
            bordered
          >
            <Descriptions.Item
              label="Login"
            >
              {r.username ||
                '—'}
            </Descriptions.Item>
            <Descriptions.Item
              label="Name"
            >
              {r.display_name ||
                '—'}
            </Descriptions.Item>
            <Descriptions.Item
              label="DN"
            >
              {r.dn || '—'}
            </Descriptions.Item>
            <Descriptions.Item
              label="Admin"
            >
              {String(
                r.will_be_admin)}
            </Descriptions.Item>
          </Descriptions>
        )
      });
    } catch (e) {
      message.error(
        e.message);
    }
  };

  return (
    <Card
      title="Active Directory"
      size="small"
      style={{
        maxWidth: 860
      }}
    >
      <Alert
        style={{
          marginBottom: 16
        }}
        type="info"
        showIcon
        message={
          'Mode: ' +
          (authMode === 'ad'
            ? 'AD'
            : 'local')
        }
      />
      <Form
        form={form}
        layout="vertical"
      >
        <Row gutter={16}>
          <Col span={6}>
            <Form.Item
              name="enabled"
              label="Enable"
              valuePropName=
                "checked"
            >
              <Switch />
            </Form.Item>
          </Col>
          <Col span={10}>
            <Form.Item
              name="host"
              label="Server"
              rules={[{
                required: true
              }]}
            >
              <Input
                placeholder="dc01"
              />
            </Form.Item>
          </Col>
          <Col span={4}>
            <Form.Item
              name="port"
              label="Port"
            >
              <Input
                placeholder="389"
              />
            </Form.Item>
          </Col>
          <Col span={4}>
            <Form.Item
              name="use_ssl"
              label="LDAPS"
              valuePropName=
                "checked"
            >
              <Checkbox />
            </Form.Item>
          </Col>
        </Row>
        <Form.Item
          name="base_dn"
          label="Base DN"
          rules={[{
            required: true
          }]}
        >
          <Input
            placeholder="DC=corp,DC=local"
          />
        </Form.Item>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item
              name="bind_dn"
              label="Bind DN"
            >
              <Input
                placeholder="user@domain"
              />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item
              name="bind_password"
              label="Password"
            >
              <Input.Password
                placeholder="••••••"
              />
            </Form.Item>
          </Col>
        </Row>
        <Form.Item
          name="user_filter"
          label="Filter"
        >
          <Input
            placeholder="(&(objectClass=user)(sAMAccountName={username}))"
          />
        </Form.Item>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item
              name="admin_group"
              label="Admin Group"
            >
              <Input
                placeholder="SOC-Admins"
              />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item
              name="admin_usernames"
              label="Admins"
            >
              <Input
                placeholder="ivanov"
              />
            </Form.Item>
          </Col>
        </Row>
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
                ? 'OK'
                : 'Error'
            }
            description={
              testRes.message
            }
          />
        )}
      </Form>

      <Card
        type="inner"
        title="Search User"
        size="small"
        style={{
          marginTop: 24
        }}
      >
        <Input.Search
          placeholder="Login fragment"
          value={searchQ}
          onChange={e =>
            setSearchQ(
              e.target.value)}
          onSearch={
            userSearch
          }
          loading={searching}
          enterButton="Search"
          allowClear
        />
        {searchRes && (
          <div style={{
            marginTop: 12
          }}>
            {!searchRes.ok && (
              <Alert
                type="error"
                showIcon
                message="Error"
                description={
                  searchRes.message}
              />
            )}
            {searchRes.ok &&
              searchRes.found
                === 0 && (
              <Alert
                type="warning"
                showIcon
                message="Not found"
              />
            )}
            {searchRes.ok &&
              (searchRes.users ||
                [])
              .map(u => (
                <Card
                  key={u.dn}
                  size="small"
                  style={{
                    marginBottom: 8
                  }}
                  hoverable
                  onClick={() =>
                    inspect(
                      u.username)}
                >
                  <Space>
                    <Tag color={
                      u.will_be_admin
                        ? 'gold'
                        : 'blue'
                    }>
                      {u.username}
                    </Tag>
                    <Text>
                      {u.display_name}
                    </Text>
                  </Space>
                </Card>
              ))}
          </div>
        )}
      </Card>
    </Card>
  );
}
