import { Controller, Get, Route, Tags } from "tsoa";
import { bookCollectionService } from "../services/bookCollection.service";
import { BookCollectionDTO } from "../dto/bookCollection.dto";

@Route("bookCollections")
@Tags("BookCollections")
export class BookCollectionController extends Controller {

    @Get("/")
    public async getAllBookCollections(): Promise<BookCollectionDTO[]> {
        return bookCollectionService.getAllBookCollections();
    }
}
