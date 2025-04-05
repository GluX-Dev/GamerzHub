import express from "express"
import cors from "cors"
import https from "https"
import dotenv from "dotenv"

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000
const FRONTEND_URL = process.env.FRONTEND_URL || "https://gamerzhubgh.web.app"

// In-memory transaction tracking
const pendingTransactions = new Map()
const processedReferences = new Set()

// CORS configuration - allow requests from the frontend
app.use(
  cors({
    origin: [FRONTEND_URL, "*"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
  }),
)

// Body parsers
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Verify Paystack secret key is available
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY
if (!PAYSTACK_SECRET_KEY) {
  console.error("PAYSTACK_SECRET_KEY is not set in environment variables")
  // Don't exit in production, just log the error
  if (process.env.NODE_ENV !== "production") {
    process.exit(1)
  }
}

// Helper function to make Paystack API requests
function paystackRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "api.paystack.co",
      port: 443,
      path,
      method,
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
    }

    console.log(`Making ${method} request to Paystack: ${path}`)

    const req = https.request(options, (res) => {
      let responseData = ""

      res.on("data", (chunk) => {
        responseData += chunk
      })

      res.on("end", () => {
        try {
          const parsedData = JSON.parse(responseData)
          console.log("Paystack response status:", parsedData.status)
          resolve(parsedData)
        } catch (error) {
          console.error("Failed to parse Paystack response:", error)
          reject(new Error(`Failed to parse Paystack response: ${error.message}`))
        }
      })
    })

    req.on("error", (error) => {
      console.error("Paystack request error:", error)
      reject(new Error(`Paystack request failed: ${error.message}`))
    })

    if (data) {
      console.log("Sending data to Paystack:", {
        ...data,
        amount: data.amount,
        email: data.email,
      })
      req.write(JSON.stringify(data))
    }

    req.end()
  })
}

// Generate a unique transaction ID based on user and transaction details
function generateTransactionId(email, amount, tournamentId, registrationId) {
  return `${email}_${amount}_${tournamentId || "none"}_${registrationId || "none"}_${Date.now()}`
}

// Initialize payment with duplicate prevention
app.post("/api/payment/initialize", async (req, res) => {
  console.log("Payment initialization request received")

  try {
    const { email, amount, metadata, tournamentId, registrationId } = req.body

    if (!email || !amount) {
      console.log("Missing required fields:", { email, amount })
      return res.status(400).json({
        status: false,
        message: "Email and amount are required",
      })
    }

    // Create a unique identifier for this transaction attempt
    const transactionId = generateTransactionId(email, amount, tournamentId, registrationId)

    // Check if this exact transaction is already being processed
    if (pendingTransactions.has(transactionId)) {
      console.log("Duplicate transaction attempt detected:", transactionId)
      return res.status(409).json({
        status: false,
        message: "A similar transaction is already being processed. Please wait or check your payment status.",
      })
    }

    // Mark this transaction as pending
    pendingTransactions.set(transactionId, {
      timestamp: Date.now(),
      status: "pending",
    })

    // Convert amount to pesewa (Paystack uses pesewa for GHS, which is 1/100 of a Cedi)
    const amountInPesewa = Math.floor(Number.parseFloat(amount) * 100)

    // Construct callback URL with all necessary parameters
    const callbackUrl = `${FRONTEND_URL}/payment-callback.html?tournamentId=${tournamentId || ""}&registrationId=${registrationId || ""}`

    // Add idempotency key to metadata to prevent duplicate processing on Paystack's end
    const enhancedMetadata = {
      ...(metadata || {}),
      transaction_id: transactionId,
      idempotency_key: `${email}_${amountInPesewa}_${Date.now()}`,
    }

    const paymentData = {
      email,
      amount: amountInPesewa,
      currency: "GHS", // Explicitly set currency to Ghanaian Cedis
      metadata: enhancedMetadata,
      callback_url: callbackUrl,
    }

    console.log("Initializing payment with data:", {
      email: paymentData.email,
      amount: `${amountInPesewa} pesewas (${amount} GHS)`,
      callback_url: callbackUrl,
      transaction_id: transactionId,
    })

    const response = await paystackRequest("POST", "/transaction/initialize", paymentData)

    if (response.status) {
      // Store the reference for verification later
      pendingTransactions.set(transactionId, {
        timestamp: Date.now(),
        status: "initialized",
        reference: response.data.reference,
        amount: amountInPesewa,
        email,
      })

      // Set a cleanup timeout (30 minutes)
      setTimeout(
        () => {
          pendingTransactions.delete(transactionId)
        },
        30 * 60 * 1000,
      )
    } else {
      // If initialization failed, remove from pending
      pendingTransactions.delete(transactionId)
    }

    console.log("Payment initialization response:", {
      status: response.status,
      message: response.message,
      authorizationUrl: response.data?.authorization_url,
    })

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment initialization error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to initialize payment: " + error.message,
      error: error.message,
    })
  }
})

// Verify payment with duplicate verification prevention
app.get("/api/payment/verify", async (req, res) => {
  console.log("Payment verification request received")

  try {
    const { reference } = req.query

    if (!reference) {
      console.log("Missing reference parameter")
      return res.status(400).json({
        status: false,
        message: "Payment reference is required",
      })
    }

    // Check if this reference has already been successfully processed
    if (processedReferences.has(reference)) {
      console.log("Payment already verified successfully:", reference)
      return res.status(200).json({
        status: true,
        message: "Payment was previously verified successfully",
        data: {
          reference,
          status: "success",
          already_processed: true,
        },
      })
    }

    console.log("Verifying payment with reference:", reference)

    const response = await paystackRequest("GET", `/transaction/verify/${reference}`)

    console.log("Payment verification response:", {
      status: response.status,
      paymentStatus: response.data?.status,
      amount: response.data?.amount ? `${response.data.amount / 100} GHS` : "N/A",
      reference: response.data?.reference,
    })

    // If payment was successful, mark this reference as processed
    if (response.status && response.data?.status === "success") {
      processedReferences.add(reference)

      // Find and update the pending transaction if it exists
      for (const [id, txn] of pendingTransactions.entries()) {
        if (txn.reference === reference) {
          pendingTransactions.set(id, {
            ...txn,
            status: "completed",
          })

          // Set a cleanup timeout (keep for 1 hour for records)
          setTimeout(
            () => {
              pendingTransactions.delete(id)
            },
            60 * 60 * 1000,
          )

          break
        }
      }

      // Limit the size of processedReferences to prevent memory leaks
      if (processedReferences.size > 10000) {
        // Remove the oldest entries (convert to array, slice, convert back to set)
        const processedReferencesSet = new Set([...processedReferences].slice(-5000))
        processedReferences = processedReferencesSet
      }
    }

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment verification error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to verify payment: " + error.message,
      error: error.message,
    })
  }
})

// Root path - just return a simple JSON response
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "GamerzHub Payment Server is running",
    endpoints: [
      { method: "POST", path: "/api/payment/initialize", description: "Initialize a payment" },
      { method: "GET", path: "/api/payment/verify", description: "Verify a payment" },
      { method: "GET", path: "/api/health", description: "Health check" },
    ],
  })
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "Server is running" })
})

// Maintenance endpoint to view pending transactions (protected in production)
if (process.env.NODE_ENV !== "production") {
  app.get("/api/debug/transactions", (req, res) => {
    res.json({
      pendingCount: pendingTransactions.size,
      processedCount: processedReferences.size,
      pending: Object.fromEntries(pendingTransactions),
    })
  })
}

// Start server
app.listen(PORT, () => {
  console.log(`Payment server running on port ${PORT}`)
  console.log(`This server handles API requests from ${FRONTEND_URL}`)
})

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error)
})

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason)
})

// Periodic cleanup of stale pending transactions (every 15 minutes)
setInterval(
  () => {
    const now = Date.now()
    const staleThreshold = 2 * 60 * 60 * 1000 // 2 hours

    let staleCount = 0
    for (const [id, txn] of pendingTransactions.entries()) {
      if (now - txn.timestamp > staleThreshold) {
        pendingTransactions.delete(id)
        staleCount++
      }
    }

    if (staleCount > 0) {
      console.log(`Cleaned up ${staleCount} stale pending transactions`)
    }
  },
  15 * 60 * 1000,
)

export default app

