import {
  Controller,
  Get,
  Post,
  Delete,
  Route,
  Path,
  Body,
  Tags,
  Patch,
  Security,
} from "tsoa";
import { userService } from "../services/user.service";
import {
  UserInputDTO,
  UserInputPatchDTO,
  UserOutputDTO,
} from "../dto/user.dto";

@Route("users")
@Tags("Users")
export class UserController extends Controller {
  // Récupère tous les utilisateurs
  @Get("/")
  @Security("jwt", ["canRead"])
  public async getAllUsers(): Promise<UserOutputDTO[]> {
    return userService.getAllUsers();
  }

  // Récupère un utilisateur par ID
  @Get("{id}")
  @Security("jwt", ["canRead"])
  public async getUserById(@Path() id: number): Promise<UserOutputDTO> {
    return userService.getUserById(id);
  }

  // Crée un nouvel utilisateur
  @Post("/")
  @Security("jwt", ["canWrite"])
  public async createUser(
    @Body() requestBody: UserInputDTO,
  ): Promise<UserOutputDTO> {
    const { username, password } = requestBody;
    return userService.createUser(username, password);
  }

  // Supprime un utilisateur par ID
  @Delete("{id}")
  @Security("jwt", ["canDelete"])
  public async deleteUser(@Path() id: number): Promise<void> {
    await userService.deleteUser(id);
  }

  // Met à jour un utilisateur par ID
  @Patch("{id}")
  @Security("jwt", ["canWrite"])
  public async updateUser(
    @Path() id: number,
    @Body() requestBody: UserInputPatchDTO,
  ): Promise<UserOutputDTO> {
    const { username, password } = requestBody;
    return userService.updateUser(id, username, password);
  }
}
