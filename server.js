import express from "express"
import dotenv from "dotenv"
import { fileURLToPath } from "url"
import path from "path"
import crypto from "crypto"
import fs from "fs"
import cors from "cors"

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
  maxRetries: 5,
  baseDelay: 1000,
  maxDelay: 30000,
  requestTimeout: 45000,
  keepAliveTimeout: 65000,
  headersTimeout: 66000,
  maxConnections: 1000,
  rateLimitWindow: 15 * 60 * 1000,
  rateLimitMax: 100,
}

if (!CONFIG.hubnetApiKey || !CONFIG.paystackSecretKey) {
  console.error("❌ Missing required environment variables:")
  console.error("HUBNET_API_KEY:", Boolean(CONFIG.hubnetApiKey))
  console.error("PAYSTACK_SECRET_KEY:", Boolean(CONFIG.paystackSecretKey))
  process.exit(1)
}

const app = express()

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true)

      const allowedOrigins = [
        CONFIG.frontendUrl,
        "http://localhost:3000",
        "http://localhost:8080",
        "https://pbmserver46.onrender.com",
        "https://gamerzhub-zgua.onrender.com",
        "https://pbmdatahub.pro",
        "https://reseller.pbmdatahub.pro",
      ]

      if (allowedOrigins.includes(origin) || CONFIG.nodeEnv === "development") {
        callback(null, true)
      } else {
        callback(null, true)
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allowedHeaders: ["Content-Type", "Authorization", "Cache-Control", "X-Requested-With", "Accept", "Origin"],
    credentials: true,
    maxAge: 86400,
  }),
)

app.use(
  express.json({
    limit: "2mb",
    strict: true,
    type: "application/json",
  }),
)

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb",
    parameterLimit: 1000,
  }),
)

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("X-XSS-Protection", "1; mode=block")
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin")
  res.setHeader("X-Powered-By", "PBM-DataHub")
  next()
})

app.use((req, res, next) => {
  const start = Date.now()
  const originalSend = res.send

  res.send = function (data) {
    const duration = Date.now() - start
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`)
    originalSend.call(this, data)
  }

  next()
})

const rateLimitStore = new Map()

function rateLimit(req, res, next) {
  const clientId = req.ip || req.connection.remoteAddress || "unknown"
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
      message: "Too many requests. Please try again later.",
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
    maxAge: CONFIG.nodeEnv === "production" ? "7d" : "1h",
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
    this._filePath = path.join(__dirname, "processed_transactions.json")
    this._saveInterval = null
    this._pendingSave = false
    this._lastSaveTime = 0
    this._maxAge = 30 * 24 * 60 * 60 * 1000
    this.init()
    this.setupAutoSave()
    this.setupPeriodicCleanup()
  }

  init() {
    try {
      if (fs.existsSync(this._filePath)) {
        const data = JSON.parse(fs.readFileSync(this._filePath, "utf8"))
        const now = Date.now()

        Object.entries(data).forEach(([key, value]) => {
          if (now - value.timestamp <= this._maxAge) {
            this._store.set(key, value)
          }
        })

        console.log(`📦 Loaded ${this._store.size} valid transactions from storage`)
      }
    } catch (error) {
      console.error("❌ Error loading transaction store:", error)
      this.createBackup()
    }
    return this
  }

  createBackup() {
    if (fs.existsSync(this._filePath)) {
      try {
        const backupPath = `${this._filePath}.backup.${Date.now()}`
        fs.copyFileSync(this._filePath, backupPath)
        console.log(`💾 Created backup: ${backupPath}`)
      } catch (backupError) {
        console.error("❌ Failed to create backup:", backupError)
      }
    }
  }

  setupAutoSave() {
    this._saveInterval = setInterval(() => {
      if (this._pendingSave && Date.now() - this._lastSaveTime > 5000) {
        this.save()
      }
    }, 30000)
  }

  setupPeriodicCleanup() {
    setInterval(
      () => {
        this.cleanup()
      },
      6 * 60 * 60 * 1000,
    )
  }

  save() {
    try {
      const data = Object.fromEntries(this._store)
      const tempFilePath = `${this._filePath}.temp`

      fs.writeFileSync(tempFilePath, JSON.stringify(data, null, 2))

      if (fs.existsSync(this._filePath)) {
        fs.unlinkSync(this._filePath)
      }

      fs.renameSync(tempFilePath, this._filePath)

      this._pendingSave = false
      this._lastSaveTime = Date.now()

      console.log(`💾 Saved ${this._store.size} transactions to storage`)
    } catch (error) {
      console.error("❌ Error saving transaction store:", error)
      this._pendingSave = true
    }
  }

  scheduleSave() {
    this._pendingSave = true

    if (Date.now() - this._lastSaveTime > 30000) {
      this.save()
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
    this.scheduleSave()
    return this
  }

  get(reference) {
    return this._store.get(reference)
  }

  getAll() {
    return Array.from(this._store.entries()).map(([reference, metadata]) => ({
      reference,
      ...metadata,
    }))
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

    if (count > 0) {
      console.log(`🧹 Cleaned up ${count} old transaction records`)
      this.scheduleSave()
    }

    return count
  }

  shutdown() {
    if (this._saveInterval) {
      clearInterval(this._saveInterval)
    }

    if (this._pendingSave) {
      this.save()
    }
  }
}

const processedTransactions = new TransactionStore()

function generateReference(prefix = "DATA") {
  const timestamp = Date.now()
  const random = crypto.randomBytes(6).toString("hex")
  return `${prefix}_${timestamp}_${random}`
}

class CircuitBreaker {
  constructor(threshold = 5, timeout = 60000, monitoringPeriod = 120000) {
    this.threshold = threshold
    this.timeout = timeout
    this.monitoringPeriod = monitoringPeriod
    this.failureCount = 0
    this.lastFailureTime = null
    this.state = "CLOSED"
  }

  async call(fn) {
    if (this.state === "OPEN") {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = "HALF_OPEN"
      } else {
        throw new Error("Circuit breaker is OPEN")
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
    this.state = "CLOSED"
  }

  onFailure() {
    this.failureCount++
    this.lastFailureTime = Date.now()

    if (this.failureCount >= this.threshold) {
      this.state = "OPEN"
    }
  }
}

const paystackCircuitBreaker = new CircuitBreaker(3, 30000)
const hubnetCircuitBreaker = new CircuitBreaker(3, 60000)

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
            "User-Agent": "PBM-DataHub/2.0",
            Accept: "application/json",
            Connection: "keep-alive",
            ...options.headers,
          },
        }

        console.log(`🔄 Attempt ${attempt + 1}/${maxRetries + 1} for ${url}`)

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
          try {
            data = JSON.parse(text)
          } catch (e) {
            throw new Error(`Invalid JSON response: ${text.substring(0, 100)}...`)
          }
        } else {
          const text = await response.text()
          try {
            data = JSON.parse(text)
          } catch (e) {
            throw new Error(`Non-JSON response: ${text.substring(0, 100)}...`)
          }
        }

        return data
      } catch (error) {
        lastError = error

        if (error.name === "AbortError") {
          lastError = new Error("Request timed out")
        } else if (error.message.includes("Failed to fetch") || error.message.includes("NetworkError")) {
          lastError = new Error("Network error occurred")
        }

        if (error.message.includes("Client error") || attempt === maxRetries) {
          break
        }

        const delay = Math.min(baseDelay * Math.pow(2, attempt) + Math.random() * 1000, maxDelay)

        console.log(`⏳ Retrying in ${delay}ms... (${error.message})`)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }

    throw lastError || new Error("Maximum retry attempts exceeded")
  }

  if (circuitBreaker) {
    return circuitBreaker.call(executeRequest)
  } else {
    return executeRequest()
  }
}

async function initializePaystackPayment(payload) {
  try {
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
        timeout: 20000,
      },
    )
  } catch (error) {
    console.error("❌ Paystack initialization error:", error)
    throw new Error(`Payment initialization failed: ${error.message}`)
  }
}

async function verifyPaystackPayment(reference) {
  try {
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
        timeout: 20000,
      },
    )
  } catch (error) {
    console.error("❌ Paystack verification error:", error)
    throw new Error(`Payment verification failed: ${error.message}`)
  }
}

async function checkHubnetBalance() {
  try {
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
        timeout: 15000,
      },
    )
  } catch (error) {
    console.error("❌ Hubnet balance check error:", error)
    throw new Error(`Balance check failed: ${error.message}`)
  }
}

async function processHubnetTransaction(payload, network) {
  try {
    if (processedTransactions.has(payload.reference)) {
      const metadata = processedTransactions.get(payload.reference)
      if (metadata && metadata.hubnetResponse) {
        console.log(`♻️ Returning cached response for ${payload.reference}`)
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

    try {
      const balanceData = await checkHubnetBalance()
      if (!balanceData.status || balanceData.balance < 5) {
        throw new Error("INSUFFICIENT_HUBNET_BALANCE")
      }
    } catch (balanceError) {
      if (balanceError.message === "INSUFFICIENT_HUBNET_BALANCE") throw balanceError
      console.warn("⚠️ Balance check failed, proceeding with transaction:", balanceError.message)
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
        timeout: 45000,
        maxRetries: 3,
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

    console.log(`✅ Successfully processed transaction ${payload.reference}`)
    return data
  } catch (error) {
    console.error("❌ Error processing Hubnet transaction:", error)
    throw error
  }
}

app.get("/health", (req, res) => {
  const healthStatus = {
    status: "ok",
    message: "Server is running",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    nodeVersion: process.version,
    environment: CONFIG.nodeEnv,
    services: {
      paystack: paystackCircuitBreaker.state,
      hubnet: hubnetCircuitBreaker.state,
    },
    transactionStore: {
      size: processedTransactions._store.size,
      lastSave: new Date(processedTransactions._lastSaveTime).toISOString(),
    },
  }

  res.status(200).json(healthStatus)
})

app.get("/", (req, res) => {
  res.json({
    name: "PBM DATA HUB API",
    version: "2.0.0",
    status: "running",
    timestamp: new Date().toISOString(),
    endpoints: {
      health: "/health",
      balance: "/api/check-balance",
      payment: "/api/initiate-payment",
      purchase: "/api/process-wallet-purchase",
      verify: "/api/verify-payment/:reference",
      status: "/api/transaction-status/:reference",
      retry: "/api/retry-transaction/:reference",
    },
  })
})

app.get("/api/check-balance", async (req, res) => {
  try {
    const balanceData = await checkHubnetBalance()
    return res.json({
      status: "success",
      message: "Balance retrieved successfully",
      data: balanceData,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("❌ Error in /api/check-balance:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to retrieve balance. Please try again or contact support.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
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
        message: "Missing required payment data. Please provide amount and email.",
        timestamp: new Date().toISOString(),
      })
    }
  } else {
    if (!network || !phone || !volume || !amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data. Please provide network, phone, volume, amount, and email.",
        timestamp: new Date().toISOString(),
      })
    }

    if (!["mtn", "at", "big-time"].includes(network)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid network. Supported networks are: mtn, at, big-time",
        timestamp: new Date().toISOString(),
      })
    }

    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid phone number format. Please provide a 10-digit phone number.",
        timestamp: new Date().toISOString(),
      })
    }
  }

  const numAmount = Number(amount)
  if (isNaN(numAmount) || numAmount <= 0) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount. Please provide a valid positive number.",
      timestamp: new Date().toISOString(),
    })
  }

  if (numAmount > 10000) {
    return res.status(400).json({
      status: "error",
      message: "Amount exceeds maximum limit of ₵10,000.",
      timestamp: new Date().toISOString(),
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
      callback_url: `${CONFIG.frontendUrl}`,
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
      throw new Error("Failed to initialize payment: " + (data.message || "Unknown error"))
    }

    console.log(`💳 Payment initialized: ${paymentReference} - ₵${numAmount}`)

    return res.json({
      status: "success",
      message: "Payment initialized successfully",
      data: data.data,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("❌ Error in /api/initiate-payment:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to initialize payment. Please try again or contact support.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/process-wallet-purchase", async (req, res) => {
  const { userId, network, phone, volume, amount, email, fcmToken, transactionKey } = req.body

  if (!userId || !network || !phone || !volume || !amount || !email) {
    return res.status(400).json({
      status: "error",
      message: "Missing required data. Please provide userId, network, phone, volume, amount, and email.",
      timestamp: new Date().toISOString(),
    })
  }

  if (!["mtn", "at", "big-time"].includes(network)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid network. Supported networks are: mtn, at, big-time",
      timestamp: new Date().toISOString(),
    })
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number format. Please provide a 10-digit phone number.",
      timestamp: new Date().toISOString(),
    })
  }

  const numAmount = Number(amount)
  const numVolume = Number(volume)

  if (isNaN(numAmount) || numAmount <= 0 || isNaN(numVolume) || numVolume <= 0) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount or volume. Please provide valid positive numbers.",
      timestamp: new Date().toISOString(),
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

    console.log(`🔄 Processing wallet purchase: ${reference} - ${numVolume}MB to ${phone} (${network.toUpperCase()})`)

    try {
      const hubnetData = await processHubnetTransaction(hubnetPayload, network)

      console.log(`✅ Wallet purchase successful: ${reference}`)

      return res.json({
        status: "success",
        message: "Transaction completed successfully. Your data bundle has been processed.",
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
      console.error("❌ Hubnet transaction error:", hubnetError)

      if (hubnetError.message === "INSUFFICIENT_HUBNET_BALANCE") {
        return res.status(503).json({
          status: "error",
          errorCode: "INSUFFICIENT_HUBNET_BALANCE",
          message: "Service provider has insufficient balance. Please try again later.",
          timestamp: new Date().toISOString(),
        })
      }

      return res.status(500).json({
        status: "error",
        message: "Failed to process data bundle. Please try again or contact support.",
        error: CONFIG.nodeEnv === "development" ? hubnetError.message : undefined,
        timestamp: new Date().toISOString(),
      })
    }
  } catch (error) {
    console.error("❌ Error in /api/process-wallet-purchase:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to process purchase. Please try again or contact support.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
      timestamp: new Date().toISOString(),
    })
  }
})

app.get("/api/verify-payment/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing payment reference.",
      timestamp: new Date().toISOString(),
    })
  }

  if (processedTransactions.has(reference)) {
    const metadata = processedTransactions.get(reference)
    console.log(`♻️ Payment already processed: ${reference}`)

    return res.json({
      status: "success",
      message: "Transaction was already processed successfully.",
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
    console.log(`🔍 Verifying payment: ${reference}`)
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status) {
      return res.json({
        status: "failed",
        message: "Payment verification failed. Please try again.",
        timestamp: new Date().toISOString(),
      })
    }

    if (verifyData.data.status === "success") {
      const paymentType = verifyData.data.metadata?.paymentType || "bundle"

      if (paymentType === "wallet") {
        console.log(`💰 Wallet deposit verified: ${reference}`)
        return res.json({
          status: "success",
          message: "Wallet deposit completed successfully.",
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

        console.log(`✅ Data bundle processed: ${reference}`)

        return res.json({
          status: "success",
          message: "Transaction completed successfully. Your data bundle has been processed.",
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
        console.error("❌ Error processing Hubnet transaction:", hubnetError)

        return res.json({
          status: "pending",
          paymentStatus: "success",
          hubnetStatus: "failed",
          message:
            "Your payment was successful, but there was an issue processing your data bundle. Our team will resolve this shortly.",
          error: CONFIG.nodeEnv === "development" ? hubnetError.message : undefined,
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
        message: "Payment is still being processed. Please check back later.",
        timestamp: new Date().toISOString(),
      })
    } else {
      return res.json({
        status: "failed",
        paymentStatus: "failed",
        message: "Payment failed or was cancelled.",
        data: verifyData.data,
        timestamp: new Date().toISOString(),
      })
    }
  } catch (error) {
    console.error("❌ Error verifying payment:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to verify payment. Please try again or contact support.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
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
      message: "Missing required parameters. Please provide reference, network, phone, and volume.",
      timestamp: new Date().toISOString(),
    })
  }

  try {
    console.log(`🔄 Retrying transaction: ${reference}`)

    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status || verifyData.data.status !== "success") {
      return res.status(400).json({
        status: "error",
        message: "Cannot retry transaction. Original payment was not successful.",
        timestamp: new Date().toISOString(),
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

    console.log(`✅ Transaction retry successful: ${reference}`)

    return res.json({
      status: "success",
      message: "Transaction retry completed successfully.",
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
    console.error("❌ Error retrying transaction:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to retry transaction. Please try again or contact support.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
      timestamp: new Date().toISOString(),
    })
  }
})

app.get("/api/transaction-status/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing transaction reference.",
      timestamp: new Date().toISOString(),
    })
  }

  try {
    if (processedTransactions.has(reference)) {
      const metadata = processedTransactions.get(reference)

      return res.json({
        status: "success",
        message: "Transaction status retrieved successfully.",
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
            message: "Payment successful but data bundle not yet processed.",
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
            message: "Payment not successful or still pending.",
            data: {
              reference,
              processed: false,
              paymentStatus: verifyData.data.status,
            },
            timestamp: new Date().toISOString(),
          })
        }
      } catch (paymentError) {
        console.error("❌ Error verifying payment for transaction status:", paymentError)
        return res.json({
          status: "unknown",
          message: "Transaction reference not found or error checking payment status.",
          data: {
            reference,
            processed: false,
            error: CONFIG.nodeEnv === "development" ? paymentError.message : undefined,
          },
          timestamp: new Date().toISOString(),
        })
      }
    }
  } catch (error) {
    console.error("❌ Error checking transaction status:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to check transaction status. Please try again.",
      error: CONFIG.nodeEnv === "development" ? error.message : undefined,
      timestamp: new Date().toISOString(),
    })
  }
})

app.use("*", (req, res) => {
  res.status(404).json({
    status: "error",
    message: "Endpoint not found",
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
  })
})

app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err.stack)

  res.status(err.status || 500).json({
    status: "error",
    message: "An unexpected error occurred. Please try again or contact support.",
    error: CONFIG.nodeEnv === "development" ? err.message : undefined,
    timestamp: new Date().toISOString(),
  })
})

const cleanupInterval = setInterval(
  () => {
    const maxAgeMs = 90 * 24 * 60 * 60 * 1000
    processedTransactions.cleanup(maxAgeMs)
  },
  24 * 60 * 60 * 1000,
)

const rateLimitCleanup = setInterval(() => {
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
}, CONFIG.rateLimitWindow)

function gracefulShutdown(signal) {
  console.log(`\n📴 ${signal} received, shutting down gracefully...`)

  clearInterval(cleanupInterval)
  clearInterval(rateLimitCleanup)
  processedTransactions.shutdown()

  server.close((err) => {
    if (err) {
      console.error("❌ Error during server shutdown:", err)
      process.exit(1)
    }

    console.log("✅ Server closed successfully")
    process.exit(0)
  })

  setTimeout(() => {
    console.error("⚠️ Forced shutdown after timeout")
    process.exit(1)
  }, 30000)
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"))
process.on("SIGINT", () => gracefulShutdown("SIGINT"))

process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason)
})

process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error)
  gracefulShutdown("UNCAUGHT_EXCEPTION")
})

const server = app.listen(CONFIG.port, "0.0.0.0", () => {
  console.log(`🚀 PBM DATA HUB API Server running at ${CONFIG.baseUrl}`)
  console.log(`🔧 Node.js version: ${process.version}`)
  console.log(`🌍 Environment: ${CONFIG.nodeEnv}`)
  console.log(`🔑 Hubnet API Key configured: ${Boolean(CONFIG.hubnetApiKey)}`)
  console.log(`🔑 Paystack Secret Key configured: ${Boolean(CONFIG.paystackSecretKey)}`)
  console.log(`💾 Transaction store initialized with ${processedTransactions.getAll().length} records`)
  console.log(`⚡ Server ready to handle requests on port ${CONFIG.port}`)
})

server.keepAliveTimeout = CONFIG.keepAliveTimeout
server.headersTimeout = CONFIG.headersTimeout
server.maxConnections = CONFIG.maxConnections

export default app
