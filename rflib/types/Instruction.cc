#include <net/if.h>
#include <boost/scoped_array.hpp>

#include "Instruction.hh"

Instruction::Instruction(const Instruction& other) : TLV(other) { }

Instruction::Instruction(InstructionType type, boost::shared_array<uint8_t> value)
    : TLV(type, type_to_length(type), value) { }

Instruction::Instruction(InstructionType type, const uint8_t* value)
    : TLV(type, type_to_length(type), value) { }

Instruction::Instruction(InstructionType type, const uint32_t value)
    : TLV(type, type_to_length(type), value) { }

Instruction& Instruction::operator=(const Instruction& other) {
    if (this != &other) {
        this->init(other.getType(), other.getLength(), other.getValue());
    }
    return *this;
}

bool Instruction::operator==(const Instruction& other) {
    return (this->getType() == other.getType() and
            (memcmp(other.getValue(), this->getValue(), this->length) == 0));
}

std::string Instruction::type_to_string() const {
    switch (this->type) {
        case RFIT_METER:                return "RFIT_METER";
        case RFIT_APPLY_ACTIONS:        return "RFIT_APPLY_ACTIONS";
        case RFIT_CLEAR_ACTIONS:        return "RFIT_CLEAR_ACTIONS";
        case RFIT_WRITE_ACTIONS:        return "RFIT_WRITE_ACTIONS";
        case RFIT_WRITE_METADATA:       return "RFIT_WRITE_METADATA";
        case RFIT_GO_TABLE:             return "RFIT_GO_TABLE";
        default:                    return "UNKNOWN_ACTION";
    }
}

size_t Instruction::type_to_length(uint8_t type) {
    switch (type) {
        case RFIT_METER:
        case RFIT_APPLY_ACTIONS:
        case RFIT_CLEAR_ACTIONS:
        case RFIT_WRITE_ACTIONS:
        case RFIT_WRITE_METADATA:
        case RFIT_GO_TABLE:
        default:
            return 0;
    }
}

/**
 * Determine what byte-order the type is stored in internally
 */
byte_order Instruction::type_to_byte_order(uint8_t type) {
    switch (type) {
        case RFIT_METER:
        case RFIT_GO_TABLE:
            return ORDER_NETWORK;
        default:
            return ORDER_HOST;
    }
}

mongo::BSONObj Instruction::to_BSON() const {
    byte_order order = type_to_byte_order(type);
    return TLV::TLV_to_BSON(this, order);
}


/**
 * Constructs a new TLV object based on the given BSONObj. Converts values
 * formatted in network byte-order to host byte-order.
 *
 * It is the caller's responsibility to free the returned object. If the given
 * BSONObj is not a valid TLV, this method returns NULL.
 */
Instruction* Instruction::from_BSON(const mongo::BSONObj bson) {
    InstructionType type = (InstructionType)TLV::type_from_BSON(bson);
    if (type == 0)
        return NULL;

    byte_order order = type_to_byte_order(type);
    boost::shared_array<uint8_t> value = TLV::value_from_BSON(bson, order);

    if (value.get() == NULL)
        return NULL;

    return new Instruction(type, value);
}

namespace InstructionList {
    mongo::BSONArray to_BSON(const std::vector<Instruction> list) {
        std::vector<Instruction>::const_iterator iter;
        mongo::BSONArrayBuilder builder;

        for (iter = list.begin(); iter != list.end(); ++iter) {
            builder.append(iter->to_BSON());
        }

        return builder.arr();
    }

    /**
     * Returns a vector of Instructions extracted from 'bson'. 'bson' should be an
     * array of bson-encoded Instruction objects formatted as follows:
     * [{
     *   "type": (int),
     *   "value": (binary)
     * },
     * ...]
     *
     * If the given 'bson' is not an array, the returned vector will be empty.
     * If any instructions in the array are invalid, they will not be added to the
     * vector.
     */
    std::vector<Instruction> to_vector(std::vector<mongo::BSONElement> array) {
        std::vector<mongo::BSONElement>::iterator iter;
        std::vector<Instruction> list;

        for (iter = array.begin(); iter != array.end(); ++iter) {
            Instruction* instruction = Instruction::from_BSON(iter->Obj());

            if (instruction != NULL) {
                list.push_back(*instruction);
            }
        }

        return list;
    }
}
