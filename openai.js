import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import {
  ObjectStorageService,
  ObjectNotFoundError,
  objectStorageClient,
} from "./objectStorage";
import { openai } from "./openai";
import { z } from "zod";
import {
  insertContactSchema,
  insertNetworkingEventSchema,
  insertVoiceNoteSchema,
  insertTodoSchema,
  insertReminderSchema,
  insertEventSchema,
} from "@shared/schema";

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Get current user
  app.get("/api/auth/user", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Object Storage Routes

  // Get presigned URL for uploading
  app.post("/api/objects/upload", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const objectStorageService = new ObjectStorageService();
      const { uploadURL, objectPath } =
        await objectStorageService.getObjectEntityUploadURL(userId);
      res.json({ uploadURL, objectPath });
    } catch (error) {
      console.error("Error getting upload URL:", error);
      res.status(500).json({ error: "Failed to get upload URL" });
    }
  });

  // Finalize upload and set ACL policy
  app.post("/api/objects/finalize", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { objectPath } = req.body;

      if (!objectPath || typeof objectPath !== "string") {
        return res
          .status(400)
          .json({ error: "objectPath is required and must be a string" });
      }

      // Use centralized service method for security
      const objectStorageService = new ObjectStorageService();
      await objectStorageService.finalizeUpload(userId, objectPath);

      res.json({ success: true, objectPath });
    } catch (error: any) {
      console.error("Error finalizing upload:", error);
      if (error instanceof ObjectNotFoundError) {
        return res.status(404).json({ error: "Object not found" });
      }
      if (
        error.message &&
        (error.message.includes("Invalid") ||
          error.message.includes("Access denied"))
      ) {
        return res.status(403).json({ error: error.message });
      }
      res.status(500).json({ error: "Failed to finalize upload" });
    }
  });

  // Serve uploaded objects with ACL
  app.get("/objects/:objectPath(*)", isAuthenticated, async (req: any, res) => {
    const userId = req.user?.claims?.sub;
    const objectStorageService = new ObjectStorageService();
    try {
      // Security: Validate path structure to prevent enumeration attacks
      const requestedPath = req.path;

      // Strict path validation using regex
      const pathRegex =
        /^\/objects\/uploads\/([a-zA-Z0-9-]+)\/([a-f0-9-]{36})$/;
      const match = requestedPath.match(pathRegex);

      if (!match) {
        return res.status(403).json({ error: "Invalid object path format" });
      }

      const pathUserId = match[1];
      const objectId = match[2];

      // CRITICAL: Only allow access to objects in user's own directory
      // This provides defense-in-depth before ACL check
      if (pathUserId !== userId) {
        console.warn(
          `Access denied: User ${userId} attempted to access ${pathUserId}'s object`,
        );
        return res
          .status(403)
          .json({ error: "Access denied - path does not belong to user" });
      }

      const objectFile =
        await objectStorageService.getObjectEntityFile(requestedPath);

      // Check ACL permissions (second layer of security)
      const canAccess = await objectStorageService.canAccessObjectEntity({
        objectFile,
        userId: userId,
      });

      if (!canAccess) {
        return res
          .status(403)
          .json({ error: "Access denied - insufficient permissions" });
      }

      objectStorageService.downloadObject(objectFile, res);
    } catch (error) {
      console.error("Error checking object access:", error);
      if (error instanceof ObjectNotFoundError) {
        return res.sendStatus(404);
      }
      return res.sendStatus(500);
    }
  });

  // Networking Event Routes

  // Get all networking events for user
  app.get("/api/networking-events", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const events = await storage.getNetworkingEvents(userId);
      res.json(events);
    } catch (error) {
      console.error("Error fetching networking events:", error);
      res.status(500).json({ error: "Failed to fetch networking events" });
    }
  });

  // Get single networking event
  app.get(
    "/api/networking-events/:id",
    isAuthenticated,
    async (req: any, res) => {
      try {
        const userId = req.user.claims.sub;
        const event = await storage.getNetworkingEvent(req.params.id);
        if (!event) {
          return res.status(404).json({ error: "Networking event not found" });
        }
        // Verify user owns this event
        if (event.userId !== userId) {
          return res.status(403).json({ error: "Access denied" });
        }
        res.json(event);
      } catch (error) {
        console.error("Error fetching networking event:", error);
        res.status(500).json({ error: "Failed to fetch networking event" });
      }
    },
  );

  // Create networking event
  app.post("/api/networking-events", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // Parse body WITHOUT userId, then add it server-side
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertNetworkingEventSchema.parse({
        ...bodyWithoutUserId,
        userId,
      });
      const event = await storage.createNetworkingEvent(validatedData);
      res.json(event);
    } catch (error) {
      console.error("Error creating networking event:", error);
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Invalid event data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to create networking event" });
    }
  });

  // Update networking event
  app.patch(
    "/api/networking-events/:id",
    isAuthenticated,
    async (req: any, res) => {
      try {
        const userId = req.user.claims.sub;
        // First verify ownership
        const existingEvent = await storage.getNetworkingEvent(req.params.id);
        if (!existingEvent) {
          return res.status(404).json({ error: "Networking event not found" });
        }
        if (existingEvent.userId !== userId) {
          return res.status(403).json({ error: "Access denied" });
        }
        // Parse body WITHOUT userId to prevent privilege escalation
        const { userId: _, ...bodyWithoutUserId } = req.body;
        const validatedData = insertNetworkingEventSchema
          .partial()
          .parse(bodyWithoutUserId);
        const event = await storage.updateNetworkingEvent(
          req.params.id,
          validatedData,
        );
        res.json(event);
      } catch (error) {
        console.error("Error updating networking event:", error);
        if (error instanceof z.ZodError) {
          return res
            .status(400)
            .json({ error: "Invalid event data", details: error.errors });
        }
        res.status(500).json({ error: "Failed to update networking event" });
      }
    },
  );

  // Delete networking event
  app.delete(
    "/api/networking-events/:id",
    isAuthenticated,
    async (req: any, res) => {
      try {
        const userId = req.user.claims.sub;
        // First verify ownership
        const existingEvent = await storage.getNetworkingEvent(req.params.id);
        if (!existingEvent) {
          return res.status(404).json({ error: "Networking event not found" });
        }
        if (existingEvent.userId !== userId) {
          return res.status(403).json({ error: "Access denied" });
        }
        // Delete the event
        await storage.deleteNetworkingEvent(req.params.id);
        res.json({ success: true });
      } catch (error) {
        console.error("Error deleting networking event:", error);
        res.status(500).json({ error: "Failed to delete networking event" });
      }
    },
  );

  // Contact Routes

  // Get all contacts for user (optionally filtered by networking event or search query)
  app.get("/api/contacts", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const networkingEventId = req.query.networkingEventId as string | undefined;
      const searchQuery = req.query.q as string | undefined;

      let contacts = await storage.getContacts(userId, networkingEventId);

      // If there's a search query, filter contacts by tags, notes, and text fields
      if (searchQuery && searchQuery.trim()) {
        const searchTerm = searchQuery.toLowerCase().trim();
        contacts = contacts.filter(contact => {
          // Search in basic fields
          const textMatch =
            contact.name?.toLowerCase().includes(searchTerm) ||
            contact.company?.toLowerCase().includes(searchTerm) ||
            contact.title?.toLowerCase().includes(searchTerm) ||
            contact.email?.toLowerCase().includes(searchTerm) ||
            contact.notes?.toLowerCase().includes(searchTerm);

          // Search in AI-extracted tags
          const tagMatch = contact.tags?.some(tag =>
            tag.toLowerCase().includes(searchTerm)
          );

          return textMatch || tagMatch;
        });
      }

      res.json(contacts);
    } catch (error) {
      console.error("Error fetching contacts:", error);
      res.status(500).json({ error: "Failed to fetch contacts" });
    }
  });

  // Get all contacts for user
  app.get("/api/contacts-legacy", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const contacts = await storage.getContacts(userId);
      res.json(contacts);
    } catch (error) {
      console.error("Error fetching contacts:", error);
      res.status(500).json({ error: "Failed to fetch contacts" });
    }
  });

  // Get single contact
  app.get("/api/contacts/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const contact = await storage.getContact(req.params.id);
      if (!contact) {
        return res.status(404).json({ error: "Contact not found" });
      }
      // Verify user owns this contact
      if (contact.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      res.json(contact);
    } catch (error) {
      console.error("Error fetching contact:", error);
      res.status(500).json({ error: "Failed to fetch contact" });
    }
  });

  // Screen 1: OCR-only endpoint with enhanced GPT-5 Vision
  app.post("/api/contacts/scan-ocr", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { cardImageURL, contentType } = req.body;

      if (!cardImageURL) {
        return res.status(400).json({ error: "cardImageURL is required" });
      }

      // Default to image/jpeg if not provided (for backward compatibility)
      const imageContentType = contentType || "image/jpeg";

      // Security: Validate that the URL is from Google Cloud Storage to prevent SSRF
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(cardImageURL);
      } catch {
        console.warn("OCR scan rejected: Invalid URL format");
        return res.status(400).json({ error: "Invalid URL format" });
      }

      // Only allow HTTPS protocol
      if (parsedUrl.protocol !== "https:") {
        console.warn("OCR scan rejected: Non-HTTPS protocol");
        return res
          .status(400)
          .json({ error: "Invalid URL protocol - must use HTTPS" });
      }

      // Only allow URLs from storage.googleapis.com (Google Cloud Storage)
      if (parsedUrl.hostname !== "storage.googleapis.com") {
        console.warn("OCR scan rejected: Invalid hostname");
        return res
          .status(400)
          .json({
            error: "Invalid storage URL - must be from Google Cloud Storage",
          });
      }

      // Validate it's from our bucket by checking the path structure
      const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
      if (!bucketId) {
        console.error(
          "Server misconfiguration: DEFAULT_OBJECT_STORAGE_BUCKET_ID not set",
        );
        return res.status(500).json({ error: "Server configuration error" });
      }
      if (!parsedUrl.pathname.startsWith(`/${bucketId}/`)) {
        console.warn("OCR scan rejected: Invalid storage bucket");
        return res.status(400).json({ error: "Invalid storage bucket" });
      }

      // Extract bucket and object path from the URL
      // URL format: https://storage.googleapis.com/bucket-name/path/to/object?query
      const pathParts = parsedUrl.pathname.split("/").filter((p) => p);
      const bucketName = pathParts[0];
      const objectPath = pathParts.slice(1).join("/");

      // Download the image using the object storage client
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectPath);

      const [fileBuffer] = await file.download();
      const base64Image = fileBuffer.toString("base64");
      const dataUrl = `data:${imageContentType};base64,${base64Image}`;

      console.log("Starting OCR with GPT-4o Vision...");

      // GPT-4o Vision for business card OCR
      const completion = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text: `Analyze this image and extract business card information.

CRITICAL: First, count how many distinct business cards are visible in the image.

If MULTIPLE cards detected:
{
  "multipleCards": true,
  "cardCount": <number of cards visible>,
  "error": "Multiple business cards detected. Please scan one card at a time for accurate extraction."
}

If EXACTLY ONE card detected, extract the contact information:
{
  "multipleCards": false,
  "name": "person's full name",
  "email": "email address",
  "phone": "phone number",
  "whatsappNumber": "WhatsApp number (only if different from phone)",
  "company": "company name",
  "title": "job title",
  "website": "company or personal website URL (look for www., http://, .com, .net, .org, etc.)",
  "country": "extract country from location/address",
  "socialMedia": {
    "linkedin": "linkedin.com/in/username or null",
    "twitter": "twitter handle or null",
    "instagram": "instagram handle or null",
    "facebook": "facebook profile or null"
  }
}

CARD DETECTION RULES:
- A business card is a rectangular card with contact information (name, title, company, phone, email)
- Multiple cards = 2 or more separate cards visible in frame
- Partially visible cards still count as separate cards
- Card may be horizontal (landscape) OR vertical (portrait) orientation
- Extract all visible text regardless of layout

EXTRACTION RULES:
- If a field is not visible on the card, use null
- Look carefully for website URLs (www., .com, .net, .org, http://, https://)
- Extract social media handles/URLs if printed on card
- Be thorough - check all corners and edges of the card

Example (single card):
{
  "multipleCards": false,
  "name": "Sarah Chen",
  "email": "sarah@startup.io",
  "phone": "+1-415-555-0123",
  "whatsappNumber": null,
  "company": "AI Startup Inc",
  "title": "Founder & CEO",
  "website": "www.startup.io",
  "country": "USA",
  "socialMedia": {
    "linkedin": "linkedin.com/in/sarahchen",
    "twitter": "@sarahchen",
    "instagram": null,
    "facebook": null
  }
}

Now analyze the image:`,
              },
              {
                type: "image_url",
                image_url: {
                  url: dataUrl,
                  detail: "high",
                },
              },
            ],
          },
        ],
        response_format: { type: "json_object" },
        max_completion_tokens: 1500,
      });

      const rawResponse = completion.choices[0].message.content || "{}";
      console.log("DEBUG - Raw GPT-4o response:", rawResponse);

      let extracted: any = {};
      try {
        extracted = JSON.parse(rawResponse);
        console.log(
          "DEBUG - Parsed extracted data:",
          JSON.stringify(extracted, null, 2),
        );

        // Check if multiple cards were detected
        if (extracted.multipleCards === true) {
          console.warn(`Multiple cards detected in image (count: ${extracted.cardCount || 'unknown'})`);
          return res.status(400).json({
            error: extracted.error || "Multiple business cards detected. Please scan one card at a time for accurate extraction.",
            multipleCards: true,
            cardCount: extracted.cardCount
          });
        }

        console.log(
          "OCR extraction complete. Fields found:",
          Object.keys(extracted).filter((k) => extracted[k] && k !== 'multipleCards'),
        );
      } catch (parseError) {
        console.error("Failed to parse GPT-4o OCR response:", parseError);
        console.error("Raw response was:", rawResponse);
        // Continue with empty object - contact can still be created manually
      }

      // Validate and clean extracted data with strict rules
      const cleanedData: any = {
        name:
          extracted.name &&
          typeof extracted.name === "string" &&
          extracted.name.trim().length > 0
            ? extracted.name.trim()
            : null,
        email:
          extracted.email &&
          typeof extracted.email === "string" &&
          extracted.email.includes("@") &&
          extracted.email.length > 3
            ? extracted.email.trim()
            : null,
        phone:
          extracted.phone &&
          typeof extracted.phone === "string" &&
          extracted.phone.trim().length > 0
            ? extracted.phone.trim()
            : null,
        whatsappNumber:
          extracted.whatsappNumber &&
          typeof extracted.whatsappNumber === "string" &&
          extracted.whatsappNumber.trim().length > 0
            ? extracted.whatsappNumber.trim()
            : null,
        company:
          extracted.company &&
          typeof extracted.company === "string" &&
          extracted.company.trim().length > 0
            ? extracted.company.trim()
            : null,
        title:
          extracted.title &&
          typeof extracted.title === "string" &&
          extracted.title.trim().length > 0
            ? extracted.title.trim()
            : null,
        country:
          extracted.country &&
          typeof extracted.country === "string" &&
          extracted.country.trim().length > 0
            ? extracted.country.trim()
            : null,
        socialMedia: {
          linkedin: extracted.socialMedia?.linkedin || null,
          twitter: extracted.socialMedia?.twitter || null,
          instagram: extracted.socialMedia?.instagram || null,
          facebook: extracted.socialMedia?.facebook || null,
        },
      };

      // Log extraction quality
      const fieldsExtracted = Object.entries(cleanedData).filter(
        ([k, v]: [string, any]) => {
          if (k === "socialMedia") {
            return Object.values(v).some((sm) => sm !== null);
          }
          return v !== null;
        },
      ).length;

      console.log(
        `Successfully extracted ${fieldsExtracted} fields from business card`,
      );
      if (cleanedData.name) console.log(`  Name: ${cleanedData.name}`);
      if (cleanedData.company) console.log(`  Company: ${cleanedData.company}`);
      if (cleanedData.email) console.log(`  Email: ${cleanedData.email}`);

      // Set ACL for the uploaded image
      const objectStorageService = new ObjectStorageService();
      const normalizedPath =
        await objectStorageService.trySetObjectEntityAclPolicy(cardImageURL, {
          owner: userId,
          visibility: "private",
        });

      // Return OCR data with normalized image path for Screen 2 form
      res.json({
        ...cleanedData,
        cardImageUrl: normalizedPath,
      });
    } catch (error) {
      console.error("Error scanning card:", error);
      res
        .status(500)
        .json({
          error:
            "Failed to scan business card. Please ensure the card is clear and well-lit, then try again.",
        });
    }
  });

  // Bulk scan OCR - accepts data URL directly for batch processing
  app.post("/api/contacts/bulk-scan-ocr", isAuthenticated, async (req: any, res) => {
    try {
      const { cardImageDataUrl } = req.body;

      if (!cardImageDataUrl || !cardImageDataUrl.startsWith('data:image/')) {
        return res.status(400).json({ error: "Invalid image data URL" });
      }

      // Validate data URL format
      const dataUrlMatch = cardImageDataUrl.match(/^data:image\/(png|jpeg|jpg|webp);base64,(.+)$/);
      if (!dataUrlMatch) {
        console.error("Invalid data URL format:", cardImageDataUrl.substring(0, 100));
        return res.status(400).json({ error: "Invalid data URL format. Must be: data:image/{type};base64,{data}" });
      }

      console.log("Starting bulk OCR with GPT-4o Vision...");
      console.log("Image type:", dataUrlMatch[1], "Data length:", dataUrlMatch[2].length);

      // Limit image size (OpenAI has a 20MB limit, but we'll be more conservative)
      const base64Data = dataUrlMatch[2];
      const estimatedSizeKB = (base64Data.length * 0.75) / 1024; // base64 is ~33% larger than actual
      console.log("Estimated image size:", Math.round(estimatedSizeKB), "KB");

      if (estimatedSizeKB > 5000) { // 5MB limit
        return res.status(400).json({ error: "Image too large. Please use images under 5MB." });
      }

      // GPT-4o Vision for business card OCR
      const completion = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text: `Read this business card and extract contact information. Return clean, normalized data as JSON:
- name: full name
- email: email address
- phone: phone number
- whatsappNumber: WhatsApp if different from phone
- company: company name
- jobTitle: job title/position
- website: website URL
- linkedIn: LinkedIn URL or handle

Return null for missing fields. Normalize data (proper capitalization, clean formatting).`,
              },
              {
                type: "image_url",
                image_url: {
                  url: cardImageDataUrl,
                  detail: "high",
                },
              },
            ],
          },
        ],
        response_format: { type: "json_object" },
        max_completion_tokens: 1000,
      });

      const rawResponse = completion.choices[0].message.content || "{}";
      let extracted: any = {};

      try {
        extracted = JSON.parse(rawResponse);

        // Use GPT-4o to clean and normalize the data
        const cleanupCompletion = await openai.chat.completions.create({
          model: "gpt-4o",
          messages: [
            {
              role: "user",
              content: `Clean and normalize this contact data. Fix formatting, capitalization, phone numbers, URLs:

${JSON.stringify(extracted, null, 2)}

Return the same JSON structure with cleaned data. Ensure:
- Names are properly capitalized
- Phone numbers are in international format if possible
- URLs are complete and valid
- Email is lowercase
- Job titles are properly formatted`,
            },
          ],
          response_format: { type: "json_object" },
          max_completion_tokens: 500,
        });

        const cleanedResponse = cleanupCompletion.choices[0].message.content || "{}";
        extracted = JSON.parse(cleanedResponse);
        console.log("Successfully cleaned and normalized data with GPT-4o");

      } catch (parseError) {
        console.error("Failed to parse or clean OCR response:", parseError);
        // Continue with raw extracted data if cleanup fails
      }

      console.log("Bulk OCR extraction complete for contact");

      // Return cleaned data
      res.json({
        name: extracted.name || null,
        email: extracted.email || null,
        phone: extracted.phone || null,
        whatsappNumber: extracted.whatsappNumber || extracted.phone || null,
        company: extracted.company || null,
        jobTitle: extracted.jobTitle || null,
        website: extracted.website || null,
        linkedIn: extracted.linkedIn || null,
      });
    } catch (error: any) {
      console.error("Error in bulk OCR:", error);
      console.error("Error details:", {
        message: error.message,
        type: error.type,
        code: error.code,
        status: error.status,
      });

      // Return more specific error message
      const errorMessage = error.message || "Failed to process business card";
      res.status(500).json({
        error: errorMessage,
        details: error.type || "Unknown error"
      });
    }
  });

  // Bulk create contacts
  app.post("/api/contacts/bulk-create", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { contacts } = req.body;

      if (!Array.isArray(contacts) || contacts.length === 0) {
        return res.status(400).json({ error: "contacts array is required" });
      }

      if (contacts.length > 100) {
        return res.status(400).json({ error: "Maximum 100 contacts per batch" });
      }

      const createdContacts = [];
      const errors = [];

      for (let i = 0; i < contacts.length; i++) {
        const contactData = contacts[i];

        try {
          // Validate required field
          if (!contactData.name || contactData.name.trim().length === 0) {
            errors.push({ index: i, error: "Name is required" });
            continue;
          }

          // Create contact
          const validatedData = insertContactSchema.parse({
            ...contactData,
            userId,
          });

          const contact = await storage.createContact(validatedData);
          createdContacts.push(contact);

        } catch (error) {
          console.error(`Error creating contact ${i}:`, error);
          errors.push({
            index: i,
            error: error instanceof Error ? error.message : "Failed to create contact"
          });
        }
      }

      res.json({
        count: createdContacts.length,
        created: createdContacts,
        errors: errors.length > 0 ? errors : undefined,
      });

    } catch (error) {
      console.error("Error in bulk create:", error);
      res.status(500).json({ error: "Failed to create contacts" });
    }
  });

  // Screen 3: Create contact with form data and trigger AI processing
  app.post("/api/contacts/create", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;

      // Validate request body with Zod schema (remove userId to prevent injection)
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertContactSchema.parse({
        ...bodyWithoutUserId,
        userId,
      });

      // Create contact with validated data
      const contact = await storage.createContact(validatedData);

      // If there's a notes field with content, use AI to extract action items and tags
      if (contact.notes && contact.notes.trim()) {
        try {
          // the newest OpenAI model is "gpt-5" which was released August 7, 2025. do not change this unless explicitly requested by the user
          const completion = await openai.chat.completions.create({
            model: "gpt-5",
            messages: [
              {
                role: "user",
                content: `Analyze these notes about ${contact.name} and extract actionable items. Today is ${new Date().toISOString().split('T')[0]}.

NOTES:
"${contact.notes}"

Extract and categorize information into this exact JSON structure:
{
  "todos": [{"title": "Send proposal", "description": "Email the Q4 pricing proposal", "dueDate": "2025-11-05"}],
  "events": [{"title": "Coffee meeting", "description": "Discuss partnership at Starbucks", "eventDate": "2025-11-10T14:00:00Z", "location": "Starbucks Downtown"}],
  "reminders": [{"title": "Follow up", "description": "Check if they received the email", "reminderDate": "2025-11-08"}],
  "tags": ["investor", "AI industry", "potential partner"]
}

INSTRUCTIONS:
1. TODOS - Tasks to complete (send email, prepare document, research, etc.)
   - Include specific title and details in description
   - Convert relative dates: "tomorrow" = ${new Date(Date.now() + 86400000).toISOString().split('T')[0]}, "next week" = add 7 days, "in 3 days" = add 3 days
   - If no date mentioned, use null for dueDate

2. EVENTS - Scheduled meetings, calls, appointments
   - Must have a specific date/time mentioned or implied
   - Use ISO 8601 format for eventDate: "YYYY-MM-DDTHH:MM:SSZ"
   - If only date mentioned (no time), use "T10:00:00Z" as default
   - Extract location if mentioned, otherwise use empty string

3. REMINDERS - Follow-up actions, check-ins, things to remember
   - Different from todos - these are "remember to..." or "don't forget..."
   - Extract date if mentioned, otherwise estimate reasonable follow-up time (e.g., 1 week from now)

4. TAGS - 3-5 relevant keywords describing person's role, industry, or relationship
   - Use lowercase, concise terms
   - Examples: investor, developer, designer, client, prospect, partner, mentor, speaker, AI industry, fintech, healthcare, enterprise, startup

5. EDGE CASES:
   - If notes are vague ("follow up soon"), create reminder for 3 days from now
   - If meeting mentioned without date, DON'T create event (insufficient info)
   - Extract ALL actionable items - don't skip any
   - If no items found in a category, return empty array []

Return valid JSON only. No markdown, no explanations.`,
              },
            ],
            response_format: { type: "json_object" },
            max_completion_tokens: 1500,
          });

          let extracted: any = { todos: [], events: [], reminders: [], tags: [] };
          try {
            extracted = JSON.parse(
              completion.choices[0].message.content || "{}",
            );
          } catch (parseError) {
            console.error("Failed to parse GPT-5 tag/action extraction response:", parseError);
            console.error("Raw response was:", completion.choices[0].message.content);
            // Continue with empty arrays - contact creation succeeds even if AI fails
          }

          // Update contact with extracted tags
          if (extracted.tags && Array.isArray(extracted.tags) && extracted.tags.length > 0) {
            await storage.updateContact(contact.id, { tags: extracted.tags });
          }

          // Create todos
          if (extracted.todos && Array.isArray(extracted.todos)) {
            for (const todo of extracted.todos) {
              await storage.createTodo({
                userId,
                contactId: contact.id,
                title: todo.title,
                description: todo.description || null,
                completed: false,
                dueDate: todo.dueDate ? new Date(todo.dueDate) : null,
              });
            }
          }

          // Create events
          if (extracted.events && Array.isArray(extracted.events)) {
            for (const event of extracted.events) {
              await storage.createEvent({
                userId,
                contactId: contact.id,
                title: event.title,
                description: event.description || null,
                eventDate: new Date(event.eventDate),
                location: event.location || null,
                attendees: event.attendees || [],
              });
            }
          }

          // Create reminders
          if (extracted.reminders && Array.isArray(extracted.reminders)) {
            for (const reminder of extracted.reminders) {
              await storage.createReminder({
                userId,
                contactId: contact.id,
                title: reminder.title,
                description: reminder.description || null,
                reminderDate: new Date(reminder.reminderDate),
                completed: false,
              });
            }
          }
        } catch (aiError) {
          console.error("Error processing notes with AI:", aiError);
          // Continue even if AI processing fails
        }
      }

      res.json(contact);
    } catch (error) {
      console.error("Error creating contact:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid contact data",
          details: error.errors,
        });
      }
      res.status(500).json({ error: "Failed to create contact" });
    }
  });

  // Update contact
  app.patch("/api/contacts/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingContact = await storage.getContact(req.params.id);
      if (!existingContact) {
        return res.status(404).json({ error: "Contact not found" });
      }
      if (existingContact.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Parse body WITHOUT userId to prevent privilege escalation
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertContactSchema
        .partial()
        .parse(bodyWithoutUserId);

      // Extract tags from notes if notes are being updated
      if (validatedData.notes && validatedData.notes.trim()) {
        try {
          const completion = await openai.chat.completions.create({
            model: "gpt-5",
            messages: [
              {
                role: "user",
                content: `Extract 3-5 relevant keyword tags from these notes that describe the person's role, industry, relationship, or expertise.

NOTES:
"${validatedData.notes}"

Return JSON format:
{ "tags": ["investor", "AI industry", "potential client"] }

TAG CATEGORIES (choose most relevant):
- Role: investor, founder, CEO, developer, designer, engineer, manager, consultant, advisor, mentor
- Industry: tech, AI, fintech, healthcare, SaaS, e-commerce, blockchain, edtech, cleantech, biotech
- Relationship: client, prospect, partner, vendor, colleague, friend, referral
- Expertise: machine learning, product design, sales, marketing, operations, fundraising
- Stage: startup, enterprise, scaleup, early-stage
- Status: warm lead, active client, past client, networking contact

RULES:
- Use lowercase only
- Be specific but concise (2-3 words max per tag)
- Prioritize professional context over personal details
- If person has multiple roles, include most relevant ones
- Extract from explicit statements AND implied context
- Minimum 3 tags, maximum 5 tags

Examples:
- Notes: "Met at AI Summit. Working on ML platform for healthcare. Looking for investors." → ["founder", "AI industry", "healthcare", "fundraising", "prospect"]
- Notes: "Great conversation about their SaaS product. Wants intro to our design team." → ["SaaS", "potential partner", "product design", "warm lead"]
- Notes: "CTO at enterprise company. Can help with our B2B sales strategy." → ["CTO", "enterprise", "advisor", "B2B sales"]

Return valid JSON only.`,
              },
            ],
            response_format: { type: "json_object" },
            max_completion_tokens: 300,
          });

          let extracted: any = { tags: [] };
          try {
            extracted = JSON.parse(completion.choices[0].message.content || "{}");
          } catch (parseError) {
            console.error("Failed to parse GPT-5 tag extraction response:", parseError);
            console.error("Raw response was:", completion.choices[0].message.content);
          }

          if (extracted.tags && Array.isArray(extracted.tags)) {
            validatedData.tags = extracted.tags;
          }
        } catch (aiError) {
          console.error("Error extracting tags:", aiError);
        }
      }

      const contact = await storage.updateContact(req.params.id, validatedData);
      res.json(contact);
    } catch (error) {
      console.error("Error updating contact:", error);
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Invalid contact data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to update contact" });
    }
  });

  // Delete contact
  app.delete("/api/contacts/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingContact = await storage.getContact(req.params.id);
      if (!existingContact) {
        return res.status(404).json({ error: "Contact not found" });
      }
      if (existingContact.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Delete the contact
      await storage.deleteContact(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting contact:", error);
      res.status(500).json({ error: "Failed to delete contact" });
    }
  });

  // Voice Note Routes

  // Get voice notes for contact
  app.get(
    "/api/voice-notes/:contactId",
    isAuthenticated,
    async (req: any, res) => {
      try {
        const userId = req.user.claims.sub;
        const notes = await storage.getVoiceNotes(userId, req.params.contactId);
        res.json(notes);
      } catch (error) {
        console.error("Error fetching voice notes:", error);
        res.status(500).json({ error: "Failed to fetch voice notes" });
      }
    },
  );

  // Create voice note and process with AI
  app.post(
    "/api/contacts/:contactId/voice-notes",
    isAuthenticated,
    async (req: any, res) => {
      try {
        const userId = req.user.claims.sub;
        const contactId = req.params.contactId;

        // Validate voice note data with Zod
        const validatedVoiceNote = insertVoiceNoteSchema.parse({
          userId,
          contactId,
          transcription: req.body.transcription,
          duration: req.body.duration || null,
          extractedContext: null, // Will be filled by AI
        });

        // Get contact for context
        const contact = await storage.getContact(contactId);

        // Use GPT-5 to extract action items, events, and context
        // the newest OpenAI model is "gpt-5" which was released August 7, 2025. do not change this unless explicitly requested by the user
        const completion = await openai.chat.completions.create({
          model: "gpt-5",
          messages: [
            {
              role: "user",
              content: `Analyze this voice note transcription about ${contact?.name || "contact"} and extract actionable items. Today is ${new Date().toISOString().split('T')[0]}.

TRANSCRIPTION:
"${validatedVoiceNote.transcription}"

Extract and categorize information into this exact JSON structure:
{
  "todos": [{"title": "Send contract", "description": "Email the signed NDA to legal team", "dueDate": "2025-11-05"}],
  "events": [{"title": "Lunch meeting", "description": "Quarterly business review at Italian restaurant", "eventDate": "2025-11-12T12:30:00Z", "location": "Mario's Bistro"}],
  "reminders": [{"title": "Check status", "description": "See if they replied to investment proposal", "reminderDate": "2025-11-09"}],
  "context": "Discussed partnership opportunities and next steps for Q4 collaboration"
}

INSTRUCTIONS:
1. TODOS - Concrete tasks mentioned in the voice note
   - Action verbs: send, email, prepare, review, research, call, schedule
   - Convert dates: "tomorrow" = ${new Date(Date.now() + 86400000).toISOString().split('T')[0]}, "Monday" = calculate next Monday, "end of week" = this Friday
   - If no specific date, use null

2. EVENTS - Explicitly mentioned meetings, calls, or appointments
   - ONLY extract if date/time is clearly stated (e.g., "meeting on Thursday at 2pm", "call scheduled for Nov 5th")
   - Use ISO 8601 format: "YYYY-MM-DDTHH:MM:SSZ"
   - Default time to 10:00 if not specified
   - Extract location from context (coffee shop name, address, "their office", "video call")

3. REMINDERS - Things to follow up on or remember
   - "Remember to...", "don't forget...", "follow up on..."
   - If vague ("check in later"), set reminder for 3-5 days from today
   - If specific ("follow up next week"), calculate appropriate date

4. CONTEXT - One concise sentence summarizing the voice note
   - Focus on key topics discussed or decisions made
   - Keep under 150 characters

5. CRITICAL RULES:
   - Extract EVERY actionable item - be thorough
   - If person says "I need to..." or "I should...", create a todo
   - If meeting time is unclear ("sometime next week"), DON'T create event
   - Voice notes often contain multiple items - capture all of them
   - Return empty arrays [] for categories with no items

Return valid JSON only.`,
            },
          ],
          response_format: { type: "json_object" },
          max_completion_tokens: 800,
        });

        const extracted = JSON.parse(
          completion.choices[0].message.content || "{}",
        );

        // Create voice note with validated data + AI-extracted context
        const voiceNote = await storage.createVoiceNote({
          ...validatedVoiceNote,
          extractedContext: extracted.context || null,
        });

        // Create extracted todos
        if (extracted.todos && Array.isArray(extracted.todos)) {
          for (const todo of extracted.todos) {
            await storage.createTodo({
              userId,
              contactId,
              title: todo.title,
              description: todo.description || null,
              completed: false,
              dueDate: todo.dueDate ? new Date(todo.dueDate) : null,
            });
          }
        }

        // Create extracted events
        if (extracted.events && Array.isArray(extracted.events)) {
          for (const event of extracted.events) {
            await storage.createEvent({
              userId,
              contactId,
              title: event.title,
              description: event.description || null,
              eventDate: new Date(event.eventDate),
              location: event.location || null,
              attendees: event.attendees || [],
            });
          }
        }

        // Create extracted reminders
        if (extracted.reminders && Array.isArray(extracted.reminders)) {
          for (const reminder of extracted.reminders) {
            await storage.createReminder({
              userId,
              contactId,
              title: reminder.title,
              description: reminder.description || null,
              reminderDate: new Date(reminder.reminderDate),
              completed: false,
            });
          }
        }

        res.json(voiceNote);
      } catch (error) {
        console.error("Error creating voice note:", error);
        if (error instanceof z.ZodError) {
          return res.status(400).json({
            error: "Invalid voice note data",
            details: error.errors,
          });
        }
        res.status(500).json({ error: "Failed to create voice note" });
      }
    },
  );

  // Todo Routes

  // Get all todos for user
  app.get("/api/todos", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const contactId = req.query.contactId as string | undefined;
      const todos = await storage.getTodos(userId, contactId);
      res.json(todos);
    } catch (error) {
      console.error("Error fetching todos:", error);
      res.status(500).json({ error: "Failed to fetch todos" });
    }
  });

  // Get todos for specific contact
  app.get("/api/todos/:contactId", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const todos = await storage.getTodos(userId, req.params.contactId);
      res.json(todos);
    } catch (error) {
      console.error("Error fetching todos:", error);
      res.status(500).json({ error: "Failed to fetch todos" });
    }
  });

  // Create todo
  app.post("/api/todos", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const validatedData = insertTodoSchema.parse({ ...req.body, userId });
      const todo = await storage.createTodo(validatedData);
      res.json(todo);
    } catch (error) {
      console.error("Error creating todo:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid todo data",
          details: error.errors,
        });
      }
      res.status(500).json({ error: "Failed to create todo" });
    }
  });

  // Update todo
  app.patch("/api/todos/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingTodo = await storage.getTodo(req.params.id);
      if (!existingTodo) {
        return res.status(404).json({ error: "Todo not found" });
      }
      if (existingTodo.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Parse body WITHOUT userId to prevent privilege escalation
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertTodoSchema.partial().parse(bodyWithoutUserId);
      const todo = await storage.updateTodo(req.params.id, validatedData);
      res.json(todo);
    } catch (error) {
      console.error("Error updating todo:", error);
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Invalid todo data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to update todo" });
    }
  });

  // Delete todo
  app.delete("/api/todos/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingTodo = await storage.getTodo(req.params.id);
      if (!existingTodo) {
        return res.status(404).json({ error: "Todo not found" });
      }
      if (existingTodo.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Delete the todo
      await storage.deleteTodo(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting todo:", error);
      res.status(500).json({ error: "Failed to delete todo" });
    }
  });

  // Reminder Routes

  // Get all reminders for user
  app.get("/api/reminders", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const reminders = await storage.getReminders(userId);
      res.json(reminders);
    } catch (error) {
      console.error("Error fetching reminders:", error);
      res.status(500).json({ error: "Failed to fetch reminders" });
    }
  });

  // Get reminders for specific contact
  app.get("/api/reminders/:contactId", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const reminders = await storage.getReminders(userId, req.params.contactId);
      res.json(reminders);
    } catch (error) {
      console.error("Error fetching reminders:", error);
      res.status(500).json({ error: "Failed to fetch reminders" });
    }
  });

  // Create reminder
  app.post("/api/reminders", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const validatedData = insertReminderSchema.parse({ ...req.body, userId });
      const reminder = await storage.createReminder(validatedData);
      res.json(reminder);
    } catch (error) {
      console.error("Error creating reminder:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid reminder data",
          details: error.errors,
        });
      }
      res.status(500).json({ error: "Failed to create reminder" });
    }
  });

  // Update reminder
  app.patch("/api/reminders/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingReminder = await storage.getReminder(req.params.id);
      if (!existingReminder) {
        return res.status(404).json({ error: "Reminder not found" });
      }
      if (existingReminder.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Parse body WITHOUT userId to prevent privilege escalation
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertReminderSchema
        .partial()
        .parse(bodyWithoutUserId);
      const reminder = await storage.updateReminder(
        req.params.id,
        validatedData,
      );
      res.json(reminder);
    } catch (error) {
      console.error("Error updating reminder:", error);
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Invalid reminder data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to update reminder" });
    }
  });

  // Delete reminder
  app.delete("/api/reminders/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingReminder = await storage.getReminder(req.params.id);
      if (!existingReminder) {
        return res.status(404).json({ error: "Reminder not found" });
      }
      if (existingReminder.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Delete the reminder
      await storage.deleteReminder(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting reminder:", error);
      res.status(500).json({ error: "Failed to delete reminder" });
    }
  });

  // Event Routes

  // Get all events for user
  app.get("/api/events", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const contactId = req.query.contactId as string | undefined;
      const events = await storage.getEvents(userId, contactId);
      res.json(events);
    } catch (error) {
      console.error("Error fetching events:", error);
      res.status(500).json({ error: "Failed to fetch events" });
    }
  });

  // Get events for specific contact
  app.get("/api/events/:contactId", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const events = await storage.getEvents(userId, req.params.contactId);
      res.json(events);
    } catch (error) {
      console.error("Error fetching events:", error);
      res.status(500).json({ error: "Failed to fetch events" });
    }
  });

  // Create event
  app.post("/api/events", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const validatedData = insertEventSchema.parse({ ...req.body, userId });
      const event = await storage.createEvent(validatedData);
      res.json(event);
    } catch (error) {
      console.error("Error creating event:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid event data",
          details: error.errors,
        });
      }
      res.status(500).json({ error: "Failed to create event" });
    }
  });

  // Update event
  app.patch("/api/events/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingEvent = await storage.getEvent(req.params.id);
      if (!existingEvent) {
        return res.status(404).json({ error: "Event not found" });
      }
      if (existingEvent.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Parse body WITHOUT userId to prevent privilege escalation
      const { userId: _, ...bodyWithoutUserId } = req.body;
      const validatedData = insertEventSchema
        .partial()
        .parse(bodyWithoutUserId);
      const event = await storage.updateEvent(req.params.id, validatedData);
      res.json(event);
    } catch (error) {
      console.error("Error updating event:", error);
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Invalid event data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to update event" });
    }
  });

  // Delete event
  app.delete("/api/events/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      // First verify ownership
      const existingEvent = await storage.getEvent(req.params.id);
      if (!existingEvent) {
        return res.status(404).json({ error: "Event not found" });
      }
      if (existingEvent.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      // Delete the event
      await storage.deleteEvent(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting event:", error);
      res.status(500).json({ error: "Failed to delete event" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
