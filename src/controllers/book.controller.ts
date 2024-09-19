import { Body, Controller, Get, Patch, Path, Post, Route, Tags } from "tsoa";
import { BookDTO } from "../dto/book.dto";
import { bookService } from "../services/book.service";
import { CreateBook } from "../interfaces/CreateBookBody.interface";
import { PatchBook } from "../interfaces/PatchBookBody.interface";

@Route("books")
@Tags("Books")
export class BookController extends Controller {
  @Get("/")
  public async getAllBooks(): Promise<BookDTO[]> {
    return bookService.getAllBooks();
  }

  @Get("{id}")
  public async getBook(@Path() id: number): Promise<BookDTO | null> {
    return bookService.getBook(id);
  }

  @Post("/")
  public async createBook(@Body() book: CreateBook): Promise<BookDTO | null> {
    const result = await bookService.createBook(book);

    if (result === null) {
      this.setStatus(404);
    }

    return result;
  }

  @Patch("{id}")
  public async updateBook(
    @Path() id: number,
    @Body() book: PatchBook
  ): Promise<BookDTO | null> {
    const result = await bookService.updateBook(id, book);

    if (result === null) {
      this.setStatus(404);
    }

    return result;
  }
}