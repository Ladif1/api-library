import { StateEnum } from '../enums/bookCollectionState.enum';
import { BookDTO } from './book.dto';

export interface BookCollectionDTO {
    id?: number;
    book?: BookDTO;
    available: boolean;
    state: StateEnum;
}