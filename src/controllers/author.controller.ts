import { Controller, Get, Post, Delete, Route, Path, Body, Tags, Patch } from "tsoa";
import { authorService } from "../services/author.service";
import { AuthorDTO } from "../dto/author.dto";
import { Author } from "../models/author.model";

@Route("authors")
@Tags("Authors")
export class AuthorController extends Controller {
  // Récupère tous les auteurs
  @Get("/")
  public async getAllAuthors(): Promise<AuthorDTO[]> {
    return authorService.getAllAuthors();
  }

  // Récupère un auteur par ID
  @Get("{id}")
  public async getAuthorById(@Path() id: number): Promise<AuthorDTO | null> {
    const author = await authorService.getAuthorById(id);

    if (!author) {
      const error = new Error('Author not found');
      (error as any).status = 404;
      throw error;
    }
    return author;
  }

  // Crée un nouvel auteur
  @Post("/")
  public async createAuthor(
    @Body() requestBody: AuthorDTO
  ): Promise<AuthorDTO> {
    const { first_name, last_name } = requestBody;
    return authorService.createAuthor(first_name, last_name);
  }

  // Supprime un auteur par ID
  @Delete("{id}")
  public async deleteAuthor(@Path() id: number): Promise<void> {
    await authorService.deleteAuthor(id);
  }

  // Met à jour un auteur par ID
  @Patch("{id}")
  public async updateAuthor(
    @Path() id: number,
    @Body() requestBody: AuthorDTO
  ): Promise<AuthorDTO | null> {
    const { first_name, last_name } = requestBody;
    const response = await authorService.updateAuthor(id, first_name, last_name);

    if (response == null) {
      this.setStatus(404);
    }
    return response;
  }
}
