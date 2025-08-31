import swaggerJsdoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "MPC Wallet API",
      version: "1.0.0",
      description:
        "API untuk dompet Multi-Party Computation (MPC) dengan Shamir Secret Sharing dan simulasi Enclave.",
    },
    servers: [
      {
        url: "https://localhost:3000",
        description: "Local development server (Coordinator)",
      },
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "X-API-Key",
        },
      },
    },
    security: [
      {
        ApiKeyAuth: [],
      },
    ],
  },
  apis: ["./coordinator.mjs"], // Path to the API routes file
};

const swaggerSpec = swaggerJsdoc(options);

export default swaggerSpec;
