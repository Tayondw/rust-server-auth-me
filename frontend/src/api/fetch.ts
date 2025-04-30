// Types
interface RequestConfig {
	method?: string;
	headers?: HeadersInit;
	// TODO: Replace 'any' with specific types once API shapes are finalized
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	body?: any;
}

// Constants
const BASE_URL = "http://localhost:8080";

// Store the current CSRF token
let csrfToken: string | null = null;

// Update CSRF token from response headers
const updateCsrfTokenFromResponse = (response: Response): void => {
	const newToken = response.headers.get("X-CSRF-Token");
	if (newToken) {
		csrfToken = newToken;
	}
};

const getCsrfToken = (): string | undefined => {
	return csrfToken ?? undefined;
};

// Function to fetch initial CSRF token
const fetchCsrfToken = async (): Promise<void> => {
	try {
		const response = await fetch(`${BASE_URL}/csrf-token`, {
			method: "GET",
			credentials: "include", // Important for cookies
			headers: {
				Accept: "application/json",
			},
		});

		if (!response.ok) {
			throw new Error("Failed to fetch CSRF token");
		}

		updateCsrfTokenFromResponse(response);
	} catch (error) {
		console.error("Error fetching CSRF token:", error);
		throw error;
	}
};

const client = async <T>(
	endpoint: string,
	{ method = "GET", headers = {}, body }: RequestConfig = {},
): Promise<T> => {
	// Fetch CSRF token if we don't have one and it's not a CSRF token request
	if (!getCsrfToken() && !endpoint.includes("csrf-token")) {
		await fetchCsrfToken();
	}

	const config: RequestConfig = {
		method,
		headers: {
			"Content-Type": "application/json",
			...(csrfToken && { "X-CSRF-Token": csrfToken }),
			...headers,
		},
		...(body && { body: JSON.stringify(body) }),
	};

	const response = await fetch(`${BASE_URL}${endpoint}`, {
		...config,
		credentials: "include", // Needed for cookies
	});

	// Update CSRF token from response headers
	updateCsrfTokenFromResponse(response);

	if (!response.ok) {
		try {
			const error = await response.json();
			return Promise.reject(error);
		} catch {
			return Promise.reject({
				status: response.status,
				statusText: response.statusText,
				message: "Failed to parse error response",
			});
		}
	}

	try {
		return await response.json();
	} catch (e) {
		return Promise.reject({
			message: "Failed to parse success response",
			error: e,
		});
	}
};

export { client, fetchCsrfToken, getCsrfToken };
