import http from 'k6/http';

const target = __ENV.TARGET || 'http://127.0.0.1/';
const duration = parseInt(__ENV.DURATION || '300', 10);
const rate = parseInt(__ENV.RATE || '20', 10);
const vus = parseInt(__ENV.VUS || '10', 10);

export const options = {
  scenarios: {
    steady_rate: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: `${duration}s`,
      preAllocatedVUs: Math.max(1, vus),
      maxVUs: Math.max(1, vus * 2),
    },
  },
};

export default function () {
  http.get(target);
}
