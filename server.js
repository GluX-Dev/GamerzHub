import express from "express"
import cors from "cors"
import https from "https"
import dotenv from "dotenv"
import path from "path"
import { fileURLToPath } from "url"

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Middleware
app.use(
  cors({
    origin: ["https://gamerzhub.web.app", "http://localhost:3000"],
    credentials: true,
  }),
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, "public")))

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

    const req = https.request(options, (res) => {
      let responseData = ""

      res.on("data", (chunk) => {
        responseData += chunk
      })

      res.on("end", () => {
        try {
          const parsedData = JSON.parse(responseData)
          resolve(parsedData)
        } catch (error) {
          reject(new Error(`Failed to parse Paystack response: ${error.message}`))
        }
      })
    })

    req.on("error", (error) => {
      reject(new Error(`Paystack request failed: ${error.message}`))
    })

    if (data) {
      req.write(JSON.stringify(data))
    }

    req.end()
  })
}

// Initialize payment
app.post("/api/payment/initialize", async (req, res) => {
  try {
    const { email, amount, metadata, tournamentId, registrationId } = req.body

    if (!email || !amount) {
      return res.status(400).json({
        status: false,
        message: "Email and amount are required",
      })
    }

    // Convert amount to pesewa (Paystack uses pesewa for GHS, which is 1/100 of a Cedi)
    const amountInPesewa = Math.floor(Number.parseFloat(amount) * 100)

    // Get the host from the request
    const host = req.headers.host
    const protocol = req.headers["x-forwarded-proto"] || "http"
    const baseUrl = `${protocol}://${host}`

    // Construct callback URL with all necessary parameters
    const callbackUrl = `${baseUrl}/payment-callback.html?tournamentId=${tournamentId || ""}&registrationId=${registrationId || ""}`

    const paymentData = {
      email,
      amount: amountInPesewa,
      currency: "GHS", // Explicitly set currency to Ghanaian Cedis
      metadata: metadata || {},
      callback_url: callbackUrl,
    }

    console.log("Initializing payment with data:", {
      ...paymentData,
      amount: `${amountInPesewa} pesewas (${amount} GHS)`,
      callback_url: callbackUrl,
    })

    const response = await paystackRequest("POST", "/transaction/initialize", paymentData)

    console.log("Payment initialization response:", response)

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment initialization error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to initialize payment",
      error: error.message,
    })
  }
})

// Verify payment
app.get("/api/payment/verify", async (req, res) => {
  try {
    const { reference } = req.query

    if (!reference) {
      return res.status(400).json({
        status: false,
        message: "Payment reference is required",
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

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment verification error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to verify payment",
      error: error.message,
    })
  }
})

// Serve HTML files
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"))
})

app.get("/payment-callback", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "payment-callback.html"))
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "Server is running" })
})

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error)
})

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason)
})

export default app

