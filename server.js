import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { timingSafeEqual } from "node:crypto";

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || "https://autossial.cl")
  .split(",")
  .map((s) => s.trim());

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !ADMIN_TOKEN) {
  console.error("Faltan variables de entorno: SUPABASE_URL, SUPABASE_SECRET_KEY o ADMIN_TOKEN.");
  process.exit(1);
}

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LINK_O_HTML = /https?:\/\/|www\.|<[^>]*>/i;

// ---------- Validación ----------

function texto(valor, { min = 0, max, requerido = false, nombre }) {
  if (valor === undefined || valor === null || valor === "") {
    if (requerido) throw new ValidationError(`Falta ${nombre}.`);
    return null;
  }
  if (typeof valor !== "string") throw new ValidationError(`${nombre} no es válido.`);
  const v = valor.trim();
  if (!v) {
    if (requerido) throw new ValidationError(`Falta ${nombre}.`);
    return null;
  }
  if (v.length < min) throw new ValidationError(`${nombre} es muy corto.`);
  if (v.length > max) throw new ValidationError(`${nombre} es muy largo.`);
  if (LINK_O_HTML.test(v)) throw new ValidationError(`${nombre} no puede tener links ni código.`);
  return v;
}

function validarRating(valor) {
  if (valor === undefined || valor === null || valor === "") return null;
  const n = Number(valor);
  if (!Number.isInteger(n) || n < 1 || n > 5) throw new ValidationError("La calificación no es válida.");
  return n;
}

function validarComentario(body) {
  return {
    nombre: texto(body.nombre, { min: 2, max: 60, requerido: true, nombre: "El nombre" }),
    lugar: texto(body.lugar, { max: 60, nombre: "El lugar" }) || "Chile",
    texto: texto(body.texto, { min: 10, max: 600, requerido: true, nombre: "El comentario" }),
    rating: validarRating(body.rating),
    aprobado: false, // siempre pendiente; solo el admin lo aprueba
  };
}

function validarSolicitud(body) {
  if (body.acepta_terminos !== true) throw new ValidationError("Debes aceptar los términos.");

  const correo = texto(body.correo, { max: 120, nombre: "El correo" });
  if (correo && !EMAIL.test(correo)) throw new ValidationError("El correo no es válido.");

  let anio = null;
  if (body.anio !== undefined && body.anio !== null && body.anio !== "") {
    anio = Number(body.anio);
    const maxAnio = new Date().getFullYear() + 1;
    if (!Number.isInteger(anio) || anio < 1950 || anio > maxAnio) {
      throw new ValidationError("El año no es válido.");
    }
  }

  return {
    nombre: texto(body.nombre, { min: 2, max: 60, requerido: true, nombre: "El nombre" }),
    rut: texto(body.rut, { max: 15, nombre: "El RUT" }),
    correo,
    telefono: texto(body.telefono, { min: 8, max: 20, requerido: true, nombre: "El teléfono" }),
    marca: texto(body.marca, { min: 2, max: 40, requerido: true, nombre: "La marca" }),
    modelo: texto(body.modelo, { min: 1, max: 60, requerido: true, nombre: "El modelo" }),
    anio,
    estado: texto(body.estado, { max: 60, nombre: "El estado" }),
    kilometraje: texto(body.kilometraje, { max: 30, nombre: "El kilometraje" }),
    precio_esperado: texto(body.precio_esperado, { max: 40, nombre: "El precio" }),
    complementos: texto(body.complementos, { max: 500, nombre: "Los complementos" }),
    acepta_terminos: true,
  };
}

// ---------- Supabase (solo desde el servidor) ----------

async function sb(ruta, { method = "GET", body, prefer } = {}) {
  const headers = {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (prefer) headers.Prefer = prefer;

  const r = await fetch(`${SUPABASE_URL}/rest/v1/${ruta}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!r.ok) {
    console.error("Supabase respondió", r.status, await r.text());
    throw new Error("Error de base de datos");
  }
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}

// ---------- Seguridad ----------

function soloAdmin(req, res, next) {
  const enviado = Buffer.from(req.get("x-admin-token") || "");
  const esperado = Buffer.from(ADMIN_TOKEN);
  if (enviado.length !== esperado.length || !timingSafeEqual(enviado, esperado)) {
    return res.status(401).json({ error: "No autorizado." });
  }
  next();
}

const limitePublico = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Demasiados envíos. Intenta más tarde." },
});

const limiteAdmin = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Demasiadas solicitudes." },
});

// ---------- App ----------

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(
  cors({
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "x-admin-token"],
  })
);
app.use(express.json({ limit: "20kb" }));

app.get("/api/health", (req, res) => res.json({ ok: true }));

// Público: comentarios aprobados
app.get("/api/comentarios", async (req, res) => {
  const data = await sb(
    "comentarios?aprobado=eq.true&order=created_at.desc&select=id,nombre,lugar,texto,rating,created_at"
  );
  res.json(data);
});

// Público: nuevo comentario (queda pendiente)
app.post("/api/comentarios", limitePublico, async (req, res) => {
  if (req.body?.website) return res.status(201).json({ ok: true }); // trampa para bots
  const datos = validarComentario(req.body || {});
  await sb("comentarios", { method: "POST", body: datos, prefer: "return=minimal" });
  res.status(201).json({ ok: true, mensaje: "Gracias, tu comentario quedará pendiente de revisión." });
});

// Público: solicitud de venta
app.post("/api/solicitudes", limitePublico, async (req, res) => {
  if (req.body?.website) return res.status(201).json({ ok: true });
  const datos = validarSolicitud(req.body || {});
  await sb("solicitudes_venta", { method: "POST", body: datos, prefer: "return=minimal" });
  res.status(201).json({ ok: true, mensaje: "Recibimos tu solicitud. Te contactaremos pronto." });
});

// Admin
app.use("/api/admin", limiteAdmin, soloAdmin);

app.get("/api/admin/comentarios/pendientes", async (req, res) => {
  const data = await sb("comentarios?aprobado=eq.false&order=created_at.desc&select=*");
  res.json(data);
});

app.patch("/api/admin/comentarios/:id/aprobar", async (req, res) => {
  if (!UUID.test(req.params.id)) throw new ValidationError("ID no válido.");
  await sb(`comentarios?id=eq.${req.params.id}`, {
    method: "PATCH",
    body: { aprobado: true },
    prefer: "return=minimal",
  });
  res.json({ ok: true });
});

app.delete("/api/admin/comentarios/:id", async (req, res) => {
  if (!UUID.test(req.params.id)) throw new ValidationError("ID no válido.");
  await sb(`comentarios?id=eq.${req.params.id}`, { method: "DELETE", prefer: "return=minimal" });
  res.json({ ok: true });
});

app.get("/api/admin/solicitudes", async (req, res) => {
  const data = await sb("solicitudes_venta?order=created_at.desc&select=*");
  res.json(data);
});

// Manejo de errores
app.use((err, req, res, next) => {
  if (err instanceof ValidationError) return res.status(400).json({ error: err.message });
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Datos no válidos." });
  if (err.status && err.status < 500) return res.status(err.status).json({ error: "Solicitud no válida." });
  console.error(err);
  res.status(500).json({ error: "Error interno. Intenta más tarde." });
});

app.listen(PORT, () => {
  console.log(`Backend SIAL escuchando en puerto ${PORT}`);
});
