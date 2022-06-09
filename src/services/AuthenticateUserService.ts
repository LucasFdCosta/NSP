import { compare } from "bcryptjs";
import { sign } from "jsonwebtoken";
import { getCustomRepository } from "typeorm";
import { UsersRepositories } from "../repositories/UsersRepositories";

interface IAuthenticateRequest {
    email: string;
    password: string;
}

class AuthenticateUserService {
    async execute({email, password}: IAuthenticateRequest) {
        const usersRepositories = getCustomRepository(UsersRepositories);

        const user = await usersRepositories.findOne({
            email
        });

        if (!user) {
            throw new Error("Incorrect Email/Password")
        }

        const passwordMatch = await compare(password, user.password);

        if (!passwordMatch) {
            throw new Error("Incorrect Email/Password")
        }

        const token = sign(
            {
                email: user.email
            },
            "aa1bf4646de67fd9086cf6c79007026c",
            {
                subject: user.id,
                expiresIn: "1d"
            }
        );

        return token;
    }
}

export { AuthenticateUserService };