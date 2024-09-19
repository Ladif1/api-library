import { Book } from "../models/book.model";
import { BookCollection } from "../models/bookCollection.model";

export class BookCollectionService {
    public async getAllBookCollections(): Promise<BookCollection[]> {
        return BookCollection.findAll({
            include: [{
                model: Book,
                as: 'book'
            }]
        });
    }
}
export const bookCollectionService = new BookCollectionService();