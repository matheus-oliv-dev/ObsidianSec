import { z } from "zod";

export const subtitleCueSchema = z.object({
  startMs: z.number().nonnegative(),
  endMs: z.number().nonnegative(),
  text: z
    .string()
    .max(500, { message: "Texto da legenda muito longo" })
    .transform((val) => val.normalize("NFKC")),
}).refine((data) => data.endMs >= data.startMs, {
  message: "endMs deve ser maior ou igual a startMs",
});

export const subtitleCuesSchema = z.array(subtitleCueSchema);
