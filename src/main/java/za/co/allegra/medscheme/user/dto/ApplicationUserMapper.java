package za.co.allegra.medscheme.user.dto;

import org.mapstruct.Mapper;
import za.co.allegra.medscheme.user.domain.ApplicationUserEntity;

@Mapper(componentModel = "spring")
public interface ApplicationUserMapper {
    ApplicationUser mapFromEntityToDto(ApplicationUserEntity applicationUserEntity);
}
