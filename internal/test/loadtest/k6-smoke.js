import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = (__ENV.BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export const options = {
  vus: 1,
  iterations: 20,
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

export default function () {
  const liveness = http.get(`${BASE_URL}/api/v1/health/liveness`);
  check(liveness, {
    "liveness status is 200": (r) => r.status === 200,
  });

  const readiness = http.get(`${BASE_URL}/api/v1/health/readiness`);
  check(readiness, {
    "readiness status is 200": (r) => r.status === 200,
  });

  const startup = http.get(`${BASE_URL}/api/v1/health/startup`);
  check(startup, {
    "startup status is 200": (r) => r.status === 200,
  });

  const metrics = http.get(`${BASE_URL}/metrics`);
  check(metrics, {
    "metrics status is 200": (r) => r.status === 200,
    "metrics content type": (r) => String(r.headers["Content-Type"] || "").includes("text/plain"),
  });

  sleep(0.2);
}
