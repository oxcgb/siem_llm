import React, {
  useState, useEffect
} from 'react';
import {
  Alert, Button, Card,
  Descriptions, Space,
        Tag,
  Typography, message
} from 'antd';
import api from '../api';

const { Text } = Typography;

export default function VllmTab() {
  const [info, setInfo] =
    useState(null);
  const [upd, setUpd] =
    useState(null);
  const [modelUpd, setModelUpd] =
    useState(null);
  const [checking, setChecking] =
    useState(false);
  const [checkingModel,
    setCheckingModel] =
    useState(false);

  useEffect(() => {
    api('/api/vllm/info')
      .then(setInfo)
      .catch(e =>
        message.error(
          e.message));
  }, []);

  const checkVllmUpdate =
    async () => {
    setChecking(true);
    setUpd(null);
    try {
      setUpd(
        await api(
          '/api/vllm/check-update', {
          method: 'POST'
        }));
    } catch (e) {
      setUpd({
        ok: false,
        error: e.message
      });
    }
    setChecking(false);
  };

  const checkModelUpdate =
    async () => {
    setCheckingModel(true);
    setModelUpd(null);
    try {
      setModelUpd(
        await api(
          '/api/model/check-update'
        )
      );
    } catch (e) {
      setModelUpd({
        ok: false,
        error: e.message
      });
    }
    setCheckingModel(false);
  };

  return (
    <Card
      title="vLLM Engine"
      size="small"
      style={{
        maxWidth: 800
      }}
    >
      {info && (
        <Descriptions
          bordered
          column={1}
          size="small"
          style={{
            marginBottom: 20
          }}
        >
          <Descriptions.Item
            label="Status"
          >
            <Tag color={
              info.healthy
                ? 'green'
                : 'red'
            }>
              {info.healthy
                ? 'healthy'
                : 'down'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item
            label="Version"
          >
            {info.version}
          </Descriptions.Item>
          <Descriptions.Item
            label="Model"
          >
            <Text code>
              {info.model}
            </Text>
          </Descriptions.Item>
          {info.gpu &&
            info.gpu.name && (
            <Descriptions.Item
              label="GPU"
            >
              {info.gpu.name}
              {' ('}
              {info.gpu.used}
              {' / '}
              {info.gpu.total}
              {' GB)'}
            </Descriptions.Item>
          )}
        </Descriptions>
      )}

      <Button
        type="primary"
        onClick={
          checkVllmUpdate
        }
        loading={checking}
      >
        Check vLLM updates
      </Button>

      {upd && !upd.ok && (
        <Alert
          type="error"
          showIcon
          style={{
            marginTop: 12
          }}
          message="Error"
          description={
            upd.error}
        />
      )}
      {upd && upd.ok &&
        upd.up_to_date && (
        <Alert
          type="success"
          showIcon
          style={{
            marginTop: 12
          }}
          message={
            'OK: ' +
            upd.current}
        />
      )}
      {upd && upd.ok &&
        !upd.up_to_date && (
        <Alert
          type="warning"
          showIcon
          style={{
            marginTop: 12
          }}
          message="Updates"
          description={
            'Current: ' +
            upd.current +
            ' → ' +
            upd.latest}
        />
      )}

      <div style={{
        marginTop: 20
      }}>
        <Button
          type="primary"
          onClick={
            checkModelUpdate
          }
          loading={
            checkingModel
          }
        >
          Check model updates
        </Button>

        {modelUpd &&
          !modelUpd.ok && (
          <Alert
            type="error"
            showIcon
            style={{
              marginTop: 12
            }}
            message="Error"
            description={
              modelUpd.error}
          />
        )}

        {modelUpd &&
          modelUpd.ok && (
          <div style={{
            marginTop: 12
          }}>
            <Alert
              type="info"
              showIcon
              message={
                'Current: ' +
                modelUpd.current
              }
              description={
                'Repo: ' +
                modelUpd.repo
              }
            />
            {(modelUpd.models ||
              [])
            .map(m => (
              <div
                key={m.model}
                style={{
                  padding: '6px 0',
                  borderBottom:
                    '1px solid #f0f0f0'
                }}
              >
                <Space>
                  <Tag
                    color="blue"
                  >
                    {m.model}
                  </Tag>
                  <Text
                    type="secondary"
                  >
                    {m.downloads}
                    {' downloads'}
                  </Text>
                  <Text
                    type="secondary"
                  >
                    {m.updated}
                  </Text>
                </Space>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}
