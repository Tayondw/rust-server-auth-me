type RequestConfig = {
	method?: string;
	headers?: HeadersInit;
	// TODO: Replace 'any' with specific types once API shapes are finalized
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	body?: any;
};

const BASE_URL = "http://localhost:8080/";

async function client<T>(
	endpoint: string,
	{ method = "GET", headers = {}, body }: RequestConfig = {},
): Promise<T> {
	const config: RequestConfig = {
		method,
		headers: {
			"Content-Type": "application/json",
			"X-CSRF-Token": getCsrfToken(),
			...headers,
		},
		...(body && { body: JSON.stringify(body) }),
	};

	const response = await fetch(`${BASE_URL}${endpoint}`, {
		...config,
		credentials: "include", // Needed for CSRF tokens
	});

	if (!response.ok) {
		const error = await response.json();
		return Promise.reject(error);
	}

	return response.json();
}

function getCsrfToken(): string | undefined {
	return (
		document
			.querySelector('meta[name="csrf-token"]')
			?.getAttribute("content") ?? undefined
	);
}

export { client };
