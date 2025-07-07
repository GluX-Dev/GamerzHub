import express from "express"
import dotenv from "dotenv"
import { fileURLToPath } from "url"
import path from "path"
import crypto from "crypto"
import fs from "fs"
import cors from "cors"
import compression from "compression"

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const CONFIG = {
  port: process.env.PORT || 3000,
  frontendUrl: process.env.FRONTEND_URL || `http://localhost:${process.env.PORT || 3000}`,
  baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
  hubnetApiKey: process.env.HUBNET_API_KEY,
  paystackSecretKey: process.env.PAYSTACK_SECRET_KEY,
  nodeEnv: process.env.NODE_ENV || "development",

  maxRetries: 1,
  baseDelay: 200,
  maxDelay: 3000,
  requestTimeout: 8000,
  keepAliveTimeout: 65000,
  headersTimeout: 66000,

  rateLimitWindow: 3 * 60 * 1000,
  rateLimitMax: 500,

  maxMemoryUsage: 512 * 1024 * 1024,
  cacheCleanupInterval: 60 * 1000,

  maxSockets: 200,
  maxFreeSockets: 50,
}

if (!CONFIG.hubnetApiKey || !CONFIG.paystackSecretKey) {
  console.error("❌ Missing required environment variables")
  process.exit(1)
}


// --- Firebase Setup ---
import firebase from "firebase-admin"
if (!firebase.apps.length) {
  firebase.initializeApp({
    credential: firebase.credential.applicationDefault(),
    databaseURL: process.env.FIREBASE_DB_URL || "https://pbmdatahub-default-rtdb.firebaseio.com"
  })
}

const app = express()
// --- API Key Middleware for External API ---
app.use("/api/external", async (req, res, next) => {
  const apiKey = req.headers["x-api-key"]
  if (!apiKey) {
    return res.status(401).json({ status: "error", message: "Missing API key" })
  }
  try {
    const snap = await firebase.database().ref("apiKeys/" + apiKey).once("value")
    if (!snap.exists()) {
      return res.status(403).json({ status: "error", message: "Invalid API key" })
    }
    req.apiUser = snap.val()
    next()
  } catch (e) {
    res.status(500).json({ status: "error", message: "API key check failed" })
  }
})

// --- Helper: Get Price for Bundle ---
function getPriceForBundle(network, volume) {
  // You can update these prices as needed
  const prices = {
    mtn: { "1000": 5.4, "2000": 10.3, "3000": 13.8, "4000": 18.8, "5000": 23.3, "6000": 27.3, "8000": 35.8, "10000": 43.5, "15000": 63.5, "20000": 84.5, "25000": 106.5, "30000": 124.5 },
    at: { "1000": 4.9, "2000": 8.8, "3000": 12.8, "4000": 14.8, "5000": 21.8, "6000": 24.8, "8000": 30.8, "10000": 41.5, "15000": 59.5, "20000": 79.5, "25000": 102.5, "30000": 119.5 }
  }
  return prices[network]?.[volume] || null
}

// --- External API: Buy Data Bundle ---
app.post("/api/external/buy-data", async (req, res) => {
  const { network, phone, volume } = req.body
  const apiUser = req.apiUser
  if (!network || !phone || !volume) {
    return res.status(400).json({ status: "error", message: "Missing required fields" })
  }
  if (!["mtn", "at"].includes(network)) {
    return res.status(400).json({ status: "error", message: "Invalid network" })
  }
  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ status: "error", message: "Invalid phone number" })
  }
  const price = getPriceForBundle(network, volume)
  if (!price) {
    return res.status(400).json({ status: "error", message: "Invalid bundle volume" })
  }
  // Check user balance
  const walletRef = firebase.database().ref("wallets/" + apiUser.userId)
  const walletSnap = await walletRef.once("value")
  const balance = walletSnap.exists() ? walletSnap.val().balance : 0
  if (balance < price) {
    return res.status(402).json({ status: "error", message: "Insufficient balance" })
  }
  // Deduct balance
  await walletRef.update({ balance: balance - price })
  // Process transaction
  const reference = generateReference(network.toUpperCase() + "_API")
  const hubnetPayload = { phone, volume: volume.toString(), reference, referrer: phone }
  try {
    const hubnetData = await processHubnetTransaction(hubnetPayload, network)
    // Record order in Firebase
    await firebase.database().ref("orders/" + apiUser.userId).push({
      network, phone, volume, amount: price, reference, status: "completed", timestamp: Date.now()
    })
    res.json({ status: "success", data: { reference, hubnetData } })
  } catch (err) {
    // Refund balance if processing fails
    await walletRef.update({ balance: balance })
    res.status(500).json({ status: "error", message: "Failed to process bundle", error: err.message })
  }
})

app.set("trust proxy", 1)

app.use(
  compression({
    level: 3,
    threshold: 256,
    filter: (req, res) => {
      if (req.headers["x-no-compression"]) return false
      return compression.filter(req, res)
    },
  }),
)

const allowedOrigins = new Set([
  CONFIG.frontendUrl,
  "http://localhost:3000",
  "http://localhost:8080",
  "https://pbmserver46.onrender.com",
  "https://pbmdatahub.pro",
  "https://reseller.pbmdatahub.pro",
])

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.has(origin) || CONFIG.nodeEnv === "development") {
        callback(null, true)
      } else {
        callback(null, false)
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cache-Control", "X-Requested-With", "Accept", "Origin"],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 204,
  }),
)

app.use(
  express.json({
    limit: "256kb",
    strict: true,
    type: "application/json",
  }),
)

app.use(
  express.urlencoded({
    extended: false,
    limit: "256kb",
    parameterLimit: 100,
  }),
)

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Powered-By": "PBM-DataHub",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-DNS-Prefetch-Control": "off",
}

app.use((req, res, next) => {
  Object.entries(securityHeaders).forEach(([key, value]) => {
    res.setHeader(key, value)
  })
  next()
})

const rateLimitStore = new Map()

function rateLimit(req, res, next) {
  const clientId = req.ip || "unknown"
  const now = Date.now()
  const windowStart = now - CONFIG.rateLimitWindow

  if (!rateLimitStore.has(clientId)) {
    rateLimitStore.set(clientId, [])
  }

  const requests = rateLimitStore.get(clientId)
  const validRequests = requests.filter((time) => time > windowStart)

  if (validRequests.length >= CONFIG.rateLimitMax) {
    return res.status(429).json({
      status: "error",
      message: "Too many requests",
      retryAfter: Math.ceil(CONFIG.rateLimitWindow / 1000),
    })
  }

  validRequests.push(now)
  rateLimitStore.set(clientId, validRequests)
  next()
}

app.use(rateLimit)

const publicDir = path.join(__dirname, "public")
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true })
}

app.use(
  express.static(publicDir, {
    maxAge: CONFIG.nodeEnv === "production" ? "1d" : "1h",
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
      if (path.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-cache")
      }
    },
  }),
)

class TransactionStore {
  constructor() {
    this._store = new Map()
    this._maxAge = 6 * 60 * 60 * 1000
    this._maxSize = 2000
    this.setupPeriodicCleanup()
  }

  setupPeriodicCleanup() {
    setInterval(() => {
      this.cleanup()
      this.memoryCleanup()
    }, CONFIG.cacheCleanupInterval)
  }

  memoryCleanup() {
    if (this._store.size > this._maxSize) {
      const entries = Array.from(this._store.entries())
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp)
      const toDelete = entries.slice(0, this._store.size - this._maxSize)
      toDelete.forEach(([key]) => this._store.delete(key))
    }
  }

  has(reference) {
    return this._store.has(reference)
  }

  add(reference, metadata = {}) {
    this._store.set(reference, {
      timestamp: Date.now(),
      ...metadata,
    })
    return this
  }

  get(reference) {
    return this._store.get(reference)
  }

  cleanup(maxAgeMs = this._maxAge) {
    const now = Date.now()
    let count = 0

    for (const [reference, metadata] of this._store.entries()) {
      if (now - metadata.timestamp > maxAgeMs) {
        this._store.delete(reference)
        count++
      }
    }

    return count
  }
}

const processedTransactions = new TransactionStore()

function generateReference(prefix = "DATA") {
  const timestamp = Date.now()
  const random = crypto.randomBytes(2).toString("hex")
  return `${prefix}_${timestamp}_${random}`
}

class CircuitBreaker {
  constructor(threshold = 2, timeout = 5000) {
    this.threshold = threshold
    this.timeout = timeout
    this.failureCount = 0
    this.lastFailureTime = null
    this.state = "CLOSED"
    this.successCount = 0
  }

  async call(fn) {
    if (this.state === "OPEN") {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = "HALF_OPEN"
      } else {
        throw new Error("Service temporarily unavailable")
      }
    }

    try {
      const result = await fn()
      this.onSuccess()
      return result
    } catch (error) {
      this.onFailure()
      throw error
    }
  }

  onSuccess() {
    this.failureCount = 0
    this.successCount++

    if (this.state === "HALF_OPEN") {
      this.state = "CLOSED"
      this.successCount = 0
    }
  }

  onFailure() {
    this.failureCount++
    this.lastFailureTime = Date.now()
    this.successCount = 0

    if (this.failureCount >= this.threshold) {
      this.state = "OPEN"
    }
  }
}

const paystackCircuitBreaker = new CircuitBreaker(2, 5000)
const hubnetCircuitBreaker = new CircuitBreaker(2, 10000)

const fetchWithRetry = async (url, options = {}, config = {}) => {
  const {
    maxRetries = CONFIG.maxRetries,
    baseDelay = CONFIG.baseDelay,
    maxDelay = CONFIG.maxDelay,
    timeout = CONFIG.requestTimeout,
    circuitBreaker = null,
  } = config

  let lastError = null

  const executeRequest = async () => {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), timeout)

        const fetchOptions = {
          ...options,
          signal: controller.signal,
          headers: {
            "User-Agent": "PBM-DataHub/5.0",
            Accept: "application/json",
            Connection: "keep-alive",
            ...options.headers,
          },
        }

        const response = await fetch(url, fetchOptions)
        clearTimeout(timeoutId)

        if (!response.ok) {
          const errorText = await response.text()
          let errorData

          try {
            errorData = JSON.parse(errorText)
          } catch {
            errorData = { message: errorText || `HTTP ${response.status}` }
          }

          if (response.status >= 400 && response.status < 500 && response.status !== 429) {
            throw new Error(`Client error: ${errorData.message || response.status}`)
          }

          throw new Error(`Server error: ${errorData.message || response.status}`)
        }

        const contentType = response.headers.get("content-type")
        let data

        if (contentType && contentType.includes("application/json")) {
          const text = await response.text()
          data = JSON.parse(text)
        } else {
          const text = await response.text()
          data = JSON.parse(text)
        }

        return data
      } catch (error) {
        lastError = error

        if (error.name === "AbortError") {
          lastError = new Error("Request timeout")
        } else if (error.message.includes("Failed to fetch")) {
          lastError = new Error("Network error")
        }

        if (error.message.includes("Client error") || attempt === maxRetries) {
          break
        }

        const delay = Math.min(baseDelay * Math.pow(1.5, attempt), maxDelay)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }

    throw lastError || new Error("Request failed")
  }

  if (circuitBreaker) {
    return circuitBreaker.call(executeRequest)
  } else {
    return executeRequest()
  }
}

async function initializePaystackPayment(payload) {
  return await fetchWithRetry(
    "https://api.paystack.co/transaction/initialize",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${CONFIG.paystackSecretKey}`,
      },
      body: JSON.stringify(payload),
    },
    {
      circuitBreaker: paystackCircuitBreaker,
      timeout: 6000,
    },
  )
}

async function verifyPaystackPayment(reference) {
  return await fetchWithRetry(
    `https://api.paystack.co/transaction/verify/${reference}`,
    {
      headers: {
        Authorization: `Bearer ${CONFIG.paystackSecretKey}`,
        "Cache-Control": "no-cache",
      },
    },
    {
      circuitBreaker: paystackCircuitBreaker,
      timeout: 6000,
    },
  )
}

async function checkHubnetBalance() {
  return await fetchWithRetry(
    "https://console.hubnet.app/live/api/context/business/transaction/check_balance",
    {
      method: "GET",
      headers: {
        token: `Bearer ${CONFIG.hubnetApiKey}`,
        "Content-Type": "application/json",
      },
    },
    {
      circuitBreaker: hubnetCircuitBreaker,
      timeout: 5000,
    },
  )
}

async function processHubnetTransaction(payload, network) {
  if (processedTransactions.has(payload.reference)) {
    const metadata = processedTransactions.get(payload.reference)
    if (metadata && metadata.hubnetResponse) {
      return metadata.hubnetResponse
    }
    return {
      status: true,
      reason: "Already processed",
      code: "transaction already processed",
      message: "0000",
      transaction_id: `TXN-${payload.reference}`,
      reference: payload.reference,
      data: {
        status: true,
        code: "0000",
        message: "Order already processed.",
      },
    }
  }

  const apiUrl = `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`

  const data = await fetchWithRetry(
    apiUrl,
    {
      method: "POST",
      headers: {
        token: `Bearer ${CONFIG.hubnetApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    },
    {
      circuitBreaker: hubnetCircuitBreaker,
      timeout: 12000,
      maxRetries: 0,
    },
  )

  if (
    data.event === "charge.rejected" &&
    data.status === "failed" &&
    data.message &&
    data.message.includes("insufficient")
  ) {
    throw new Error("INSUFFICIENT_HUBNET_BALANCE")
  }

  if (data.status === "failed") {
    const errorMessage = data.message || data.reason || "Transaction failed"
    throw new Error(`Hubnet API error: ${errorMessage}`)
  }

  processedTransactions.add(payload.reference, {
    network,
    phone: payload.phone,
    volume: payload.volume,
    hubnetResponse: data,
    processedAt: new Date().toISOString(),
  })

  return data
}

app.get("/health", (req, res) => {
  const memUsage = process.memoryUsage()
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
    environment: CONFIG.nodeEnv,
    services: {
      paystack: paystackCircuitBreaker.state,
      hubnet: hubnetCircuitBreaker.state,
    },
  })
})

app.get("/", (req, res) => {
  res.json({
    name: "PBM DATA HUB API",
    version: "5.0.0",
    status: "running",
    timestamp: new Date().toISOString(),
  })
})

app.get("/api/check-balance", async (req, res) => {
  try {
    const balanceData = await checkHubnetBalance()
    res.json({
      status: "success",
      data: balanceData,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Failed to retrieve balance",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/initiate-payment", async (req, res) => {
  const { network, phone, volume, amount, email, fcmToken, paymentType, reference } = req.body

  if (paymentType === "wallet") {
    if (!amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data",
      })
    }
  } else {
    if (!network || !phone || !volume || !amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data",
      })
    }

    if (!["mtn", "at", "big-time"].includes(network)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid network",
      })
    }

    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid phone number format",
      })
    }
  }

  const numAmount = Number(amount)
  if (isNaN(numAmount) || numAmount <= 0 || numAmount > 10000) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount",
    })
  }

  try {
    const prefix =
      paymentType === "wallet"
        ? "WALLET_DEPOSIT"
        : network === "mtn"
          ? "MTN_DATA"
          : network === "at"
            ? "AT_DATA"
            : "BT_DATA"

    const paymentReference = reference || generateReference(prefix)
    const amountInKobo = Math.round(numAmount * 100)

    const payload = {
      amount: amountInKobo,
      email,
      reference: paymentReference,
      callback_url: CONFIG.frontendUrl,
      metadata: {
        paymentType: paymentType || "bundle",
        fcmToken: fcmToken || null,
        custom_fields: [
          {
            display_name: paymentType === "wallet" ? "Wallet Deposit" : "Data Bundle",
            variable_name: paymentType === "wallet" ? "wallet_deposit" : "data_bundle",
            value:
              paymentType === "wallet"
                ? `₵${numAmount} Wallet Deposit`
                : `${volume}MB for ${phone} (${network.toUpperCase()})`,
          },
        ],
      },
    }

    if (paymentType !== "wallet") {
      payload.metadata.network = network
      payload.metadata.phone = phone
      payload.metadata.volume = volume
    }

    const data = await initializePaystackPayment(payload)

    if (!data.status || !data.data) {
      throw new Error("Payment initialization failed")
    }

    res.json({
      status: "success",
      data: data.data,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Payment initialization failed",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/process-wallet-purchase", async (req, res) => {
  const { userId, network, phone, volume, amount, email, fcmToken, transactionKey } = req.body

  if (!userId || !network || !phone || !volume || !amount || !email) {
    return res.status(400).json({
      status: "error",
      message: "Missing required data",
    })
  }

  if (!["mtn", "at", "big-time"].includes(network)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid network",
    })
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number",
    })
  }

  const numAmount = Number(amount)
  const numVolume = Number(volume)

  if (isNaN(numAmount) || numAmount <= 0 || isNaN(numVolume) || numVolume <= 0) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount or volume",
    })
  }

  try {
    const prefix = network === "mtn" ? "MTN_PBM" : network === "at" ? "AT_PBM" : "BT_WALLET"
    const reference = generateReference(prefix)

    const hubnetPayload = {
      phone,
      volume: numVolume.toString(),
      reference,
      referrer: phone,
    }

    const hubnetData = await processHubnetTransaction(hubnetPayload, network)

    res.json({
      status: "success",
      message: "Transaction completed successfully",
      data: {
        reference: reference,
        amount: numAmount,
        phone: phone,
        volume: numVolume,
        network: network,
        timestamp: Date.now(),
        transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
        hubnetResponse: hubnetData,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (hubnetError) {
    if (hubnetError.message === "INSUFFICIENT_HUBNET_BALANCE") {
      return res.status(503).json({
        status: "error",
        errorCode: "INSUFFICIENT_HUBNET_BALANCE",
        message: "Service provider has insufficient balance",
        timestamp: new Date().toISOString(),
      })
    }

    res.status(500).json({
      status: "error",
      message: "Failed to process data bundle",
      timestamp: new Date().toISOString(),
    })
  }
})

app.get("/api/verify-payment/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing payment reference",
    })
  }

  if (processedTransactions.has(reference)) {
    const metadata = processedTransactions.get(reference)
    return res.json({
      status: "success",
      message: "Transaction already processed",
      data: {
        reference: reference,
        alreadyProcessed: true,
        processedAt: metadata.processedAt || new Date().toISOString(),
        hubnetResponse: metadata.hubnetResponse || null,
      },
      timestamp: new Date().toISOString(),
    })
  }

  try {
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status) {
      return res.json({
        status: "failed",
        message: "Payment verification failed",
        timestamp: new Date().toISOString(),
      })
    }

    if (verifyData.data.status === "success") {
      const paymentType = verifyData.data.metadata?.paymentType || "bundle"

      if (paymentType === "wallet") {
        return res.json({
          status: "success",
          message: "Wallet deposit completed successfully",
          data: {
            reference: verifyData.data.reference,
            amount: verifyData.data.amount / 100,
            paymentType: "wallet",
            timestamp: new Date(verifyData.data.paid_at).getTime(),
          },
          timestamp: new Date().toISOString(),
        })
      }

      const { phone, volume, network } = verifyData.data.metadata
      const hubnetPayload = {
        phone,
        volume: volume.toString(),
        reference,
        referrer: phone,
      }

      try {
        const hubnetData = await processHubnetTransaction(hubnetPayload, network)

        return res.json({
          status: "success",
          message: "Transaction completed successfully",
          data: {
            reference: verifyData.data.reference,
            amount: verifyData.data.amount / 100,
            phone: verifyData.data.metadata.phone,
            volume: verifyData.data.metadata.volume,
            network: verifyData.data.metadata.network,
            timestamp: new Date(verifyData.data.paid_at).getTime(),
            transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
            hubnetResponse: hubnetData,
          },
          timestamp: new Date().toISOString(),
        })
      } catch (hubnetError) {
        return res.json({
          status: "pending",
          paymentStatus: "success",
          hubnetStatus: "failed",
          message: "Payment successful but data bundle processing failed",
          data: {
            reference: verifyData.data.reference,
            amount: verifyData.data.amount / 100,
            phone: verifyData.data.metadata.phone,
            volume: verifyData.data.metadata.volume,
            network: verifyData.data.metadata.network,
            timestamp: new Date(verifyData.data.paid_at).getTime(),
          },
          timestamp: new Date().toISOString(),
        })
      }
    } else if (verifyData.data.status === "pending") {
      return res.json({
        status: "pending",
        paymentStatus: "pending",
        message: "Payment is being processed",
        timestamp: new Date().toISOString(),
      })
    } else {
      return res.json({
        status: "failed",
        paymentStatus: "failed",
        message: "Payment failed",
        data: verifyData.data,
        timestamp: new Date().toISOString(),
      })
    }
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Payment verification failed",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/retry-transaction/:reference", async (req, res) => {
  const { reference } = req.params
  const { network, phone, volume } = req.body

  if (!reference || !network || !phone || !volume) {
    return res.status(400).json({
      status: "error",
      message: "Missing required parameters",
    })
  }

  try {
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status || verifyData.data.status !== "success") {
      return res.status(400).json({
        status: "error",
        message: "Cannot retry transaction",
      })
    }

    const hubnetPayload = {
      phone,
      volume: volume.toString(),
      reference,
      referrer: phone,
    }

    let existingData = null
    if (processedTransactions.has(reference)) {
      existingData = processedTransactions.get(reference)
      processedTransactions.add(reference, {
        ...existingData,
        retryAttempted: true,
        retryTimestamp: Date.now(),
      })
    }

    const hubnetData = await processHubnetTransaction(hubnetPayload, network)

    res.json({
      status: "success",
      message: "Transaction retry completed",
      data: {
        reference,
        phone,
        volume,
        network,
        timestamp: Date.now(),
        transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
        hubnetResponse: hubnetData,
        previousAttempt: existingData ? true : false,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Transaction retry failed",
      timestamp: new Date().toISOString(),
    })
  }
})

app.get("/api/transaction-status/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing transaction reference",
    })
  }

  try {
    if (processedTransactions.has(reference)) {
      const metadata = processedTransactions.get(reference)

      return res.json({
        status: "success",
        message: "Transaction status retrieved",
        data: {
          reference,
          processed: true,
          processedAt: metadata.processedAt || new Date(metadata.timestamp).toISOString(),
          details: metadata,
        },
        timestamp: new Date().toISOString(),
      })
    } else {
      try {
        const verifyData = await verifyPaystackPayment(reference)

        if (verifyData.status && verifyData.data.status === "success") {
          return res.json({
            status: "pending",
            message: "Payment successful but data bundle not processed",
            data: {
              reference,
              processed: false,
              paymentStatus: "success",
              paymentDetails: {
                amount: verifyData.data.amount / 100,
                phone: verifyData.data.metadata?.phone,
                volume: verifyData.data.metadata?.volume,
                network: verifyData.data.metadata?.network,
                paidAt: verifyData.data.paid_at,
              },
            },
            timestamp: new Date().toISOString(),
          })
        } else {
          return res.json({
            status: "pending",
            message: "Payment not successful or pending",
            data: {
              reference,
              processed: false,
              paymentStatus: verifyData.data.status,
            },
            timestamp: new Date().toISOString(),
          })
        }
      } catch (paymentError) {
        return res.json({
          status: "unknown",
          message: "Transaction reference not found",
          data: {
            reference,
            processed: false,
          },
          timestamp: new Date().toISOString(),
        })
      }
    }
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Failed to check transaction status",
      timestamp: new Date().toISOString(),
    })
  }
})

app.use("*", (req, res) => {
  res.status(404).json({
    status: "error",
    message: "Endpoint not found",
    path: req.originalUrl,
  })
})

app.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    status: "error",
    message: "Server error occurred",
  })
})

setInterval(() => {
  const now = Date.now()
  const windowStart = now - CONFIG.rateLimitWindow

  for (const [clientId, requests] of rateLimitStore.entries()) {
    const validRequests = requests.filter((time) => time > windowStart)
    if (validRequests.length === 0) {
      rateLimitStore.delete(clientId)
    } else {
      rateLimitStore.set(clientId, validRequests)
    }
  }

  processedTransactions.cleanup()
}, CONFIG.cacheCleanupInterval)

const server = app.listen(CONFIG.port, "0.0.0.0", () => {
  console.log(`🚀 PBM DATA HUB API Server v5.0 running on port ${CONFIG.port}`)
  console.log(`🌍 Environment: ${CONFIG.nodeEnv}`)
  console.log(`⚡ Optimized for Render hosting`)
})

server.keepAliveTimeout = CONFIG.keepAliveTimeout
server.headersTimeout = CONFIG.headersTimeout
server.timeout = CONFIG.requestTimeout

export default app
