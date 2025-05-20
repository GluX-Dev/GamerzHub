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

const app = express()
const port = process.env.PORT || 3000
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${port}`
const BASE_URL = process.env.BASE_URL || `http://localhost:${port}`

const HUBNET_API_KEY = process.env.HUBNET_API_KEY
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY

if (!HUBNET_API_KEY || !PAYSTACK_SECRET_KEY) {
  console.error("Missing required environment variables. Please check your .env file.")
  console.error("HUBNET_API_KEY:", Boolean(HUBNET_API_KEY))
  console.error("PAYSTACK_SECRET_KEY:", Boolean(PAYSTACK_SECRET_KEY))
}

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cache-Control"]
}))
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))

const publicDir = path.join(__dirname, "public")
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true })
app.use(express.static(publicDir, {
  maxAge: '1d',
  etag: true
}))

class TransactionStore {
  constructor() {
    this._store = new Map()
    this._filePath = path.join(__dirname, "processed_transactions.json")
    this._saveInterval = null
    this._pendingSave = false
    this._lastSaveTime = 0
    this.init()
    this.setupAutoSave()
  }

  init() {
    try {
      if (fs.existsSync(this._filePath)) {
        const data = JSON.parse(fs.readFileSync(this._filePath, "utf8"))
        
        const now = Date.now()
        const maxAgeMs = 30 * 24 * 60 * 60 * 1000
        
        Object.entries(data).forEach(([key, value]) => {
          if (now - value.timestamp <= maxAgeMs) {
            this._store.set(key, value)
          }
        })
        
        console.log(`Loaded ${this._store.size} valid transactions from storage`)
      }
    } catch (error) {
      console.error("Error loading transaction store:", error)
      if (fs.existsSync(this._filePath)) {
        try {
          fs.copyFileSync(this._filePath, `${this._filePath}.backup.${Date.now()}`)
          console.log("Created backup of corrupted transaction store file")
        } catch (backupError) {
          console.error("Failed to create backup of corrupted file:", backupError)
        }
      }
    }
    return this
  }

  setupAutoSave() {
    this._saveInterval = setInterval(() => {
      if (this._pendingSave && Date.now() - this._lastSaveTime > 5000) {
        this.save()
      }
    }, 300000)
  }

  save() {
    try {
      const data = Object.fromEntries(this._store)
      
      const tempFilePath = `${this._filePath}.temp`
      fs.writeFileSync(tempFilePath, JSON.stringify(data, null, 2))
      fs.renameSync(tempFilePath, this._filePath)
      
      this._pendingSave = false
      this._lastSaveTime = Date.now()
    } catch (error) {
      console.error("Error saving transaction store:", error)
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
    this._store.set(reference, { timestamp: Date.now(), ...metadata })
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

  cleanup(maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
    const now = Date.now()
    let count = 0

    for (const [reference, metadata] of this._store.entries()) {
      if (now - metadata.timestamp > maxAgeMs) {
        this._store.delete(reference)
        count++
      }
    }

    if (count > 0) {
      console.log(`Cleaned up ${count} old transaction records`)
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
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`
}

const fetchWithRetry = async (url, options = {}, maxRetries = 3, baseDelay = 1000, timeout = 15000) => {
  let retries = 0
  let lastError = null

  while (retries <= maxRetries) {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), timeout)
      
      const fetchOptions = {
        ...options,
        signal: controller.signal,
      }
      
      const response = await fetch(url, fetchOptions)
      clearTimeout(timeoutId)
      
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
      
      if (!response.ok) {
        const errorMessage = data.message || data.reason || response.statusText
        throw new Error(`API error: ${errorMessage}. Status code: ${response.status}`)
      }
      
      return data
    } catch (error) {
      lastError = error
      retries++
      
      if (error.message.includes("Status code: 4")) {
        throw error
      }
      
      if (error.name === "AbortError") {
        console.error(`Request timed out (attempt ${retries}/${maxRetries})`)
      } else {
        console.error(`Fetch error (attempt ${retries}/${maxRetries}):`, error.message)
      }
      
      if (retries > maxRetries) break
      
      const delay = baseDelay * Math.pow(2, retries - 1) * (0.9 + Math.random() * 0.2)
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }
  
  throw lastError || new Error("Maximum retries exceeded")
}

async function initializePaystackPayment(payload) {
  try {
    return await fetchWithRetry(
      "https://api.paystack.co/transaction/initialize",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
        body: JSON.stringify(payload),
      },
      3,
      1000,
      15000
    )
  } catch (error) {
    console.error("Paystack initialization error:", error)
    throw new Error(`Payment initialization failed: ${error.message}`)
  }
}

async function verifyPaystackPayment(reference) {
  try {
    return await fetchWithRetry(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          "Cache-Control": "no-cache",
        },
      },
      3,
      1000,
      15000
    )
  } catch (error) {
    console.error("Paystack verification error:", error)
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
          token: `Bearer ${HUBNET_API_KEY}`,
          "Content-Type": "application/json",
        },
      },
      3,
      1000,
      15000
    )
  } catch (error) {
    console.error("Hubnet balance check error:", error)
    throw new Error(`Balance check failed: ${error.message}`)
  }
}

async function processHubnetTransaction(payload, network) {
  try {
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

    try {
      const balanceData = await checkHubnetBalance()
      if (!balanceData.status || balanceData.balance < 5) {
        throw new Error("INSUFFICIENT_HUBNET_BALANCE")
      }
    } catch (balanceError) {
      if (balanceError.message === "INSUFFICIENT_HUBNET_BALANCE") throw balanceError
      console.warn("Balance check failed, proceeding with transaction:", balanceError.message)
    }

    const apiUrl = `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`
    
    const data = await fetchWithRetry(
      apiUrl,
      {
        method: "POST",
        headers: {
          token: `Bearer ${HUBNET_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      },
      3,
      1000,
      30000
    )
    
    if (data.event === "charge.rejected" && data.status === "failed" && 
        data.message && data.message.includes("insufficient")) {
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
  } catch (error) {
    console.error("Error processing Hubnet transaction:", error)
    throw error
  }
}

app.get("/", (req, res) => {
  res.send("PBM DATA HUB API Server is running")
})

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    message: "Server is running",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    nodeVersion: process.version
  })
})

app.get("/api/check-balance", async (req, res) => {
  try {
    const balanceData = await checkHubnetBalance()
    return res.json({
      status: "success",
      message: "Balance retrieved successfully",
      data: balanceData,
    })
  } catch (error) {
    console.error("Error in /api/check-balance:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to retrieve balance. Please try again or contact support.",
      error: error.message,
    })
  }
})

app.post("/api/initiate-payment", async (req, res) => {
  const { network, phone, volume, amount, email, fcmToken, paymentType } = req.body

  if (paymentType === "wallet") {
    if (!amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data. Please provide amount and email.",
      })
    }
  } else {
    if (!network || !phone || !volume || !amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data. Please provide network, phone, volume, amount, and email.",
      })
    }

    if (!["mtn", "at", "big-time"].includes(network)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid network. Supported networks are: mtn, at, big-time",
      })
    }

    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid phone number format. Please provide a 10-digit phone number.",
      })
    }
  }

  try {
    let prefix = paymentType === "wallet" ? "WALLET_DEPOSIT" : 
                 network === "mtn" ? "MTN_DATA" : 
                 network === "at" ? "AT_DATA" : "BT_DATA"
    const reference = generateReference(prefix)
    const amountInKobo = Math.round(amount * 100)

    const payload = {
      amount: amountInKobo,
      email,
      reference,
      callback_url: `${FRONTEND_URL}`,
      metadata: {
        paymentType: paymentType || "bundle",
        fcmToken: fcmToken || null,
        custom_fields: [
          {
            display_name: paymentType === "wallet" ? "Wallet Deposit" : "Data Bundle",
            variable_name: paymentType === "wallet" ? "wallet_deposit" : "data_bundle",
            value: paymentType === "wallet" ? `₵${amount} Wallet Deposit` : `${volume}MB for ${phone} (${network.toUpperCase()})`,
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

    return res.json({
      status: "success",
      message: "Payment initialized successfully",
      data: data.data,
    })
  } catch (error) {
    console.error("Error in /api/initiate-payment:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to initialize payment. Please try again or contact support.",
      error: error.message,
    })
  }
})

app.post("/api/process-wallet-purchase", async (req, res) => {
  const { userId, network, phone, volume, amount, email, fcmToken } = req.body

  if (!userId || !network || !phone || !volume || !amount || !email) {
    return res.status(400).json({
      status: "error",
      message: "Missing required data. Please provide userId, network, phone, volume, amount, and email.",
    })
  }

  if (!["mtn", "at", "big-time"].includes(network)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid network. Supported networks are: mtn, at, big-time",
    })
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number format. Please provide a 10-digit phone number.",
    })
  }

  try {
    const prefix = network === "mtn" ? "MTN_PBM" : network === "at" ? "AT_PBM" : "BT_WALLET"
    const reference = generateReference(prefix)

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
        message: "Transaction completed successfully. Your data bundle has been processed.",
        data: {
          reference: reference,
          amount: Number.parseFloat(amount),
          phone: phone,
          volume: volume,
          network: network,
          timestamp: Date.now(),
          transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
          hubnetResponse: hubnetData,
        },
      })
    } catch (hubnetError) {
      console.error("Hubnet transaction error:", hubnetError)

      if (hubnetError.message === "INSUFFICIENT_HUBNET_BALANCE") {
        return res.status(503).json({
          status: "error",
          errorCode: "INSUFFICIENT_HUBNET_BALANCE",
          message: "Service provider has insufficient balance. Please try again later.",
        })
      }

      return res.status(500).json({
        status: "error",
        message: "Failed to process data bundle. Please try again or contact support.",
        error: hubnetError.message,
      })
    }
  } catch (error) {
    console.error("Error in /api/process-wallet-purchase:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to process purchase. Please try again or contact support.",
      error: error.message,
    })
  }
})

app.get("/api/verify-payment/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing payment reference.",
    })
  }

  if (processedTransactions.has(reference)) {
    const metadata = processedTransactions.get(reference)
    return res.json({
      status: "success",
      message: "Transaction was already processed successfully.",
      data: {
        reference: reference,
        alreadyProcessed: true,
        processedAt: metadata.processedAt || new Date().toISOString(),
        hubnetResponse: metadata.hubnetResponse || null,
      },
    })
  }

  try {
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status) {
      return res.json({
        status: "failed",
        message: "Payment verification failed. Please try again.",
      })
    }

    if (verifyData.data.status === "success") {
      const paymentType = verifyData.data.metadata?.paymentType || "bundle"

      if (paymentType === "wallet") {
        return res.json({
          status: "success",
          message: "Wallet deposit completed successfully.",
          data: {
            reference: verifyData.data.reference,
            amount: verifyData.data.amount / 100,
            paymentType: "wallet",
            timestamp: new Date(verifyData.data.paid_at).getTime(),
          },
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
        })
      } catch (hubnetError) {
        console.error("Error processing Hubnet transaction:", hubnetError)

        return res.json({
          status: "pending",
          paymentStatus: "success",
          hubnetStatus: "failed",
          message: "Your payment was successful, but there was an issue processing your data bundle. Our team will resolve this shortly.",
          error: hubnetError.message,
          data: {
            reference: verifyData.data.reference,
            amount: verifyData.data.amount / 100,
            phone: verifyData.data.metadata.phone,
            volume: verifyData.data.metadata.volume,
            network: verifyData.data.metadata.network,
            timestamp: new Date(verifyData.data.paid_at).getTime(),
          },
        })
      }
    } else if (verifyData.data.status === "pending") {
      return res.json({
        status: "pending",
        paymentStatus: "pending",
        message: "Payment is still being processed. Please check back later.",
      })
    } else {
      return res.json({
        status: "failed",
        paymentStatus: "failed",
        message: "Payment failed or was cancelled.",
        data: verifyData.data,
      })
    }
  } catch (error) {
    console.error("Error verifying payment:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to verify payment. Please try again or contact support.",
      error: error.message,
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
    })
  }

  try {
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status || verifyData.data.status !== "success") {
      return res.status(400).json({
        status: "error",
        message: "Cannot retry transaction. Original payment was not successful.",
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
    })
  } catch (error) {
    console.error("Error retrying transaction:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to retry transaction. Please try again or contact support.",
      error: error.message,
    })
  }
})

app.get("/api/transaction-status/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing transaction reference.",
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
          })
        }
      } catch (paymentError) {
        console.error("Error verifying payment for transaction status:", paymentError)
        return res.json({
          status: "unknown",
          message: "Transaction reference not found or error checking payment status.",
          data: {
            reference,
            processed: false,
            error: paymentError.message,
          },
        })
      }
    }
  } catch (error) {
    console.error("Error checking transaction status:", error)
    return res.status(500).json({
      status: "error",
      message: "Failed to check transaction status. Please try again.",
      error: error.message,
    })
  }
})

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack)
  res.status(500).json({
    status: "error",
    message: "An unexpected error occurred. Please try again or contact support.",
    error: process.env.NODE_ENV === "production" ? undefined : err.message,
  })
})

const cleanupInterval = setInterval(() => {
  const maxAgeMs = 90 * 24 * 60 * 60 * 1000
  processedTransactions.cleanup(maxAgeMs)
}, 24 * 60 * 60 * 1000)

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully')
  clearInterval(cleanupInterval)
  processedTransactions.shutdown()
  server.close(() => {
    console.log('Server closed')
    process.exit(0)
  })
})

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully')
  clearInterval(cleanupInterval)
  processedTransactions.shutdown()
  server.close(() => {
    console.log('Server closed')
    process.exit(0)
  })
})

const server = app.listen(port, () => {
  console.log(`🚀 Server running at ${BASE_URL}`)
  console.log(`🔧 Node.js version: ${process.version}`)
  console.log("🔑 Hubnet API Key configured:", Boolean(HUBNET_API_KEY))
  console.log("🔑 Paystack Secret Key configured:", Boolean(PAYSTACK_SECRET_KEY))
  console.log(`💾 Transaction store initialized with ${processedTransactions.getAll().length} records`)
})
