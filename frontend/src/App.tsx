import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MantineProvider } from "@mantine/core";
import { SignUp } from "./pages/SignUp";
// import { Login } from './pages/Login';
// import { Home } from './pages/Home';

const queryClient = new QueryClient();

function App() {
	return (
		<QueryClientProvider client={queryClient}>
			<MantineProvider>
				<BrowserRouter>
					<Routes>
						{/* <Route path="/" element={<Home />} /> */}
						<Route path="/signup" element={<SignUp />} />
						{/* <Route path="/login" element={<Login />} /> */}
					</Routes>
				</BrowserRouter>
			</MantineProvider>
		</QueryClientProvider>
	);
}

export default App;
