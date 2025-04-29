import { useForm } from "@mantine/form";
import {
	TextInput,
	PasswordInput,
	Checkbox,
	Button,
	Stack,
} from "@mantine/core";
import { useMutation } from "@tanstack/react-query";
import { signUp } from "../api/auth";
import type { SignUpRequest } from "../api/auth";

export function SignUp() {
	const form = useForm<SignUpRequest>({
		initialValues: {
			name: "",
			username: "",
			email: "",
			password: "",
			verify_password: "",
			terms_accepted: false,
		},
		validate: {
			email: (value) => (/^\S+@\S+$/.test(value) ? null : "Invalid email"),
			password: (value) =>
				value.length < 8 ? "Password must be at least 8 characters" : null,
			verify_password: (value, values) =>
				value !== values.password ? "Passwords do not match" : null,
		},
	});

	const mutation = useMutation({
		mutationFn: signUp,
		onSuccess: (data) => {
			console.log("Signup successful:", data);
			// Handle successful signup (e.g., redirect, show message)
		},
		onError: (error: Error) => {
			console.error("Signup failed:", error);
			// Handle error (e.g., show error message)
		},
	});

	const handleSubmit = form.onSubmit((values) => {
		mutation.mutate(values);
	});

	return (
		<form onSubmit={handleSubmit}>
			<Stack gap="md">
				<TextInput required label="Name" {...form.getInputProps("name")} />
				<TextInput
					required
					label="Username"
					{...form.getInputProps("username")}
				/>
				<TextInput required label="Email" {...form.getInputProps("email")} />
				<PasswordInput
					required
					label="Password"
					{...form.getInputProps("password")}
				/>
				<PasswordInput
					required
					label="Confirm Password"
					{...form.getInputProps("verify_password")}
				/>
				<Checkbox
					label="I accept the terms and conditions"
					{...form.getInputProps("terms_accepted", { type: "checkbox" })}
				/>
				<Button
					type="submit"
					loading={mutation.isPending}
					disabled={!form.isValid()}
				>
					Sign Up
				</Button>
			</Stack>
		</form>
	);
}
