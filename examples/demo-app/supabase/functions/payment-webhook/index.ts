// Called by a payment provider, not by the app. verify_jwt = false in config.toml makes it an external entry point.
Deno.serve(async (req) => new Response(await req.text()));
