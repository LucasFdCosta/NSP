import { getCustomRepository } from "typeorm";
import { ComplimentRepositories } from "../repositories/ComplimentsRepositories";

class ListUserSentComplimentsService {
  async execute(user_id: string) {
    const complimentsRepositories = getCustomRepository(ComplimentRepositories);

    const compliments = complimentsRepositories.find({
      where: {
        user_sender: user_id
      },
      relations: ["userSender", "userReceiver", "tag"]
    })

    return compliments;
  }
}

export { ListUserSentComplimentsService };