import { getCustomRepository } from "typeorm";
import { ComplimentRepositories } from "../repositories/ComplimentsRepositories";
import { TagsRepositories } from "../repositories/TagsRepositories";
import { UsersRepositories } from "../repositories/UsersRepositories";

interface IComplimentRequest {
    tag_id: string;
    user_sender: string;
    user_receiver: string;
    message: string;
}

class CreateComplimentService {
    async execute({ tag_id, user_sender, user_receiver, message }: IComplimentRequest) {
        const complimentsRepositories = getCustomRepository(ComplimentRepositories);
        const usersRepositories = getCustomRepository(UsersRepositories);
        const tagRepositories = getCustomRepository(TagsRepositories);

        const tagExists = await tagRepositories.findOne(tag_id);

        if (!tagExists) {
            throw new Error("This tag doesn't exist!");
        }

        if (user_sender === user_receiver) {
            throw new Error("An user can't compliment himself (user sender and user receiver are equal)");
        }

        const userReceiverExists = await usersRepositories.findOne(user_receiver);

        if (!userReceiverExists) {
            throw new Error("User receiver does not exist!");
        }

        const compliment = complimentsRepositories.create({
            tag_id,
            user_receiver,
            user_sender,
            message
        })

        await complimentsRepositories.save(compliment);

        return compliment;
    }
}

export { CreateComplimentService };