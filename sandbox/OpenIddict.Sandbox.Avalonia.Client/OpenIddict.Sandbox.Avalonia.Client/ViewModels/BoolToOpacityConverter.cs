using Avalonia.Data.Converters;
using System;
using System.Globalization;

namespace OpenIddict.Sandbox.Avalonia.Client.ViewModels;

public class BoolToOpacityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if(value is bool b && b)
        {
            return 1d;
        }
        return 0.4d;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
