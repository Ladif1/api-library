import { Author } from "../models/author.model";
import { Book } from "../models/book.model";
import { authorService } from "./author.service";
import { CreateBook } from "../interfaces/CreateBookBody.interface";
import { PatchBook } from "../interfaces/PatchBookBody.interface";

export class BookService {
  public async getAllBooks(): Promise<Book[]> {
    return Book.findAll({
      include: [{
        model: Author,
        as: 'author'
      }]
    });
  }

  public async getBook(id: number): Promise<Book | null> {
    return Book.findByPk(id, {
      include: [{
        model: Author,
        as: 'author'
      }]
    });
  }

  public async createBook(book: CreateBook): Promise<Book | null> {
    if (!await authorService.getAuthorById(book.author_id)) {
      return null;
    }
    return Book.create({ title: book.title, publish_year: book.publish_year, author_id: book.author_id, isbn: book.isbn });
  }

  public async updateBook(id: number, book: PatchBook): Promise<Book | null> {
    const { title, publish_year, author_id, isbn } = book;
    const bookToUpdate = await Book.findByPk(id);

    if (!bookToUpdate) {
      return null;
    }

    if (title) {
      bookToUpdate.title = title;
    }

    if (publish_year) {
      bookToUpdate.publish_year = publish_year;
    }

    if (author_id) {
      if (!await authorService.getAuthorById(author_id)) {
        return null;
      }
      bookToUpdate.author_id = author_id;
    }

    if (isbn) {
      bookToUpdate.isbn = isbn;
    }

    await bookToUpdate.save();
    return bookToUpdate;
  }
}

export const bookService = new BookService();
