
    if (pathname === '/api/ai/analyze' && req.method === 'POST') {
      const body = await readBody(req);
      if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
      if (!geminiService.isConfigured()) return json(res, 400, { error: 'Gemini API key not configured. Set GEMINI_API_KEY env var or provide apiKey in request.' });
      try {
        const result = await geminiService.analyzeTelemetry(body);
        return json(res, 200, result);
      } catch (e) { return json(res, 500, { error: e.message }); }
    }
    if (pathname === '/api/ai/chat' && req.method === 'POST') {
      const body = await readBody(req);
      if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
      if (!geminiService.isConfigured()) return json(res, 400, { error: 'AI not configured' });
      try {
        const result = await geminiService.chat(body);
        return json(res, 200, result);
      } catch (e) { return json(res, 500, { error: e.message }); }
    }
    if (pathname === '/api/ai/metrics' && req.method === 'GET') {
      return json(res, 200, geminiService.getMetrics());
    }

    