import axios from 'axios'

// `withCredentials: true` makes the browser send the httpOnly auth cookie on
// every request to the API. That alone is not proof the request came from our
// UI, so every state-changing request also carries an anti-CSRF token that an
// attacker's page can neither read nor guess.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = new Set(['get', 'head', 'options'])

// The token is bound to the current session, so it must be dropped whenever the
// session changes (login, register, logout) and re-fetched on the next write.
let csrfToken = null

export function clearCsrfToken() {
  csrfToken = null
}

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

function setCsrfHeader(config, token) {
  if (typeof config.headers?.set === 'function') config.headers.set('x-csrf-token', token)
  else config.headers = { ...config.headers, 'x-csrf-token': token }
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.has(method) || (config.url || '').includes('/csrf-token')) return config
  setCsrfHeader(config, csrfToken ?? await fetchCsrfToken())
  return config
})

// A token minted before login is no longer valid after it. Rather than make
// every caller care, retry such a request once with a freshly minted token.
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { config, response } = error
    if (response?.status === 403 && response.data?.code === 'EBADCSRFTOKEN' && config && !config._csrfRetried) {
      config._csrfRetried = true
      clearCsrfToken()
      setCsrfHeader(config, await fetchCsrfToken())
      return api(config)
    }
    return Promise.reject(error)
  }
)
